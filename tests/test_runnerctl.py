# pyright: standard
#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from nix_adapter import ensure_subordinate_range

from runnerctl import cli, operations
from runnerctl.config import PLATFORMS, load_instances
from runnerctl.model import validate_instances

FIXTURES = Path(__file__).parent / "fixtures"
INSTANCE_FILES = [FIXTURES / "frontend.toml", FIXTURES / "dotnet.toml"]


class RunnerControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Operations look their collaborators up in this module; patch it.
        cls.runnerctl = operations

        cls.instances = load_instances(INSTANCE_FILES)
        cls.platform = PLATFORMS["arch"]

    def test_host_configuration_is_valid(self) -> None:
        validate_instances(self.instances)

    def test_empty_configuration_is_valid(self) -> None:
        validate_instances({})

    def test_operation_lock_serializes_instances(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner.lock"
            with (
                self.runnerctl.operation_lock(path),
                self.assertRaisesRegex(self.runnerctl.RunnerError, "another Runner"),
                self.runnerctl.operation_lock(path),
            ):
                self.fail("acquired twice")
            with self.runnerctl.operation_lock(path):
                pass

    def test_timeout_does_not_echo_arguments_or_output(self) -> None:
        with (
            mock.patch.object(
                self.runnerctl.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["fake", "private"], 1, output="private"),
            ),
            self.assertRaises(self.runnerctl.RunnerError) as raised,
        ):
            self.runnerctl.run(["fake", "private"], timeout=1)
        self.assertNotIn("private", str(raised.exception))

    def test_cli_accepts_no_token_argument(
        self,
    ) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "runnerctl",
                "--config",
                str(INSTANCE_FILES[0]),
                "--help",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )

        self.assertNotIn("--token", result.stdout)

    def test_progress_boundaries_use_static_labels_and_mark_failures(self) -> None:
        output = StringIO()
        instance = self.instances["frontend"]
        platform = self.platform
        with redirect_stderr(output):
            with (
                mock.patch.object(
                    self.runnerctl,
                    "check_prerequisites",
                    side_effect=self.runnerctl.RunnerError("synthetic secret"),
                ),
                self.assertRaises(self.runnerctl.RunnerError),
            ):
                self.runnerctl.check("frontend", instance, platform)
            with mock.patch.object(self.runnerctl, "_reconcile_impl", return_value=False):
                self.runnerctl.reconcile(instance, platform)
            with mock.patch.object(self.runnerctl, "_register_impl"):
                self.runnerctl.register(instance, platform)
            with mock.patch.object(self.runnerctl, "_verify_impl"):
                self.runnerctl.verify(instance, platform)
            with mock.patch.object(self.runnerctl, "_status_impl"):
                self.runnerctl.status("frontend", instance, platform)

        rendered = output.getvalue()
        self.assertIn("[failed] Running check", rendered)
        self.assertIn("[done] Reconciling Runner", rendered)
        self.assertIn("[done] Registering Runner", rendered)
        self.assertIn("[done] Verifying Runner", rendered)
        self.assertIn("[done] Inspecting Runner status", rendered)
        self.assertNotIn("synthetic secret", rendered)
        self.assertNotIn(instance["gitlab"]["url"], rendered)

    def test_overlapping_subordinate_ids_are_rejected(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["dotnet"]["account"]["subUid"]["start"] = 165536
        instances["dotnet"]["account"]["subGid"]["start"] = 165536
        with self.assertRaisesRegex(self.runnerctl.RunnerError, "overlapping subUid"):
            validate_instances(instances)

    def test_short_subordinate_id_ranges_are_rejected(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["account"]["subUid"]["count"] = 65535
        with self.assertRaisesRegex(self.runnerctl.RunnerError, "at least 65536"):
            validate_instances(instances)

    def test_gitlab_health_url_must_use_the_coordinator_hostname(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["gitlab"]["healthUrl"] = "https://other.example/health"
        with self.assertRaisesRegex(self.runnerctl.RunnerError, "same HTTPS hostname"):
            validate_instances(instances)

    def test_default_job_image_must_match_the_allowlist(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["runner"]["allowedImages"] = ["docker.io/library/python:*"]
        with self.assertRaisesRegex(self.runnerctl.RunnerError, "match allowedImages"):
            validate_instances(instances)

    def test_required_interface_is_optional_and_not_vpn_specific(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["network"]["requiredInterface"] = None
        validate_instances(instances)

    def test_registered_config_preserves_registration_metadata(self) -> None:
        instance = self.instances["frontend"]
        test_value = "test-only-value"
        metadata = {
            "id": "42",
            "token": test_value,
            "token_obtained_at": "2026-01-02T03:04:05Z",
        }
        rendered = self.runnerctl.render_config(instance, metadata)
        self.assertIn(f'token = "{test_value}"', rendered)
        self.assertIn("id = 42", rendered)
        self.assertIn("token_obtained_at = 2026-01-02T03:04:05Z", rendered)
        self.assertIn('host = "unix:///run/podman/podman.sock"', rendered)
        self.assertIn("privileged = false", rendered)

    def test_registered_config_uses_the_managed_ca_when_declared(self) -> None:
        instance = copy.deepcopy(self.instances["frontend"])
        instance["gitlab"]["caCertificate"] = "/nix/store/public-runner-ca.crt"
        instance["artifacts"]["configPolicy"]["caLine"] = (
            '  tls-ca-file = "/etc/gitlab-runner/certs/gitlab.example.crt"\n'
        )

        rendered = self.runnerctl.render_config(instance, {"token": "test-only-value"})

        self.assertIn(
            'tls-ca-file = "/etc/gitlab-runner/certs/gitlab.example.crt"',
            rendered,
        )

    def test_registration_metadata_rejects_multiple_runners(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text('[[runners]]\ntoken = "one"\n[[runners]]\ntoken = "two"\n')
            with self.assertRaisesRegex(self.runnerctl.RunnerError, "multiple registrations"):
                self.runnerctl.registration_metadata(config)

    def test_registration_metadata_rejects_incomplete_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text('[[runners]]\nname = "incomplete"\n')
            with self.assertRaisesRegex(self.runnerctl.RunnerError, "incomplete"):
                self.runnerctl.registration_metadata(config)

    def test_registration_metadata_ignores_tokens_outside_a_runner_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text('token = "orphaned-marker"\n')

            self.assertEqual(self.runnerctl.registration_metadata(config), {})

    def test_registration_metadata_is_scoped_and_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                'token = "outside"\n[[runners]]\nid = 42\ntoken = "inside\\"quoted"\ntoken_obtained_at = 2026-01-02T03:04:05Z\n[runners.docker]\ntoken = "nested"\n'
            )
            metadata = self.runnerctl.registration_metadata(path)
            self.assertEqual(metadata["token"], 'inside"quoted')
            path.write_text(self.runnerctl.render_config(self.instances["frontend"], metadata))
            self.assertEqual(self.runnerctl.registration_metadata(path), metadata)

    def test_invalid_registration_is_redacted_and_not_rewritten(self):
        for body in (
            'token = "private"\ntoken = "private"',
            'id = true\ntoken = "private"',
            "token = 123",
            'token = "private"\ntoken_expires_at = "private"',
        ):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "config.toml"
                content = "[[runners]]\n" + body
                path.write_text(content)
                with self.assertRaises(self.runnerctl.RunnerError) as raised:
                    self.runnerctl.registration_metadata(path)
                self.assertNotIn("private", str(raised.exception))
                self.assertEqual(path.read_text(), content)

    def test_reconcile_checks_prerequisites_before_mutating_accounts(self) -> None:
        instance = self.instances["frontend"]
        with (
            mock.patch.object(self.runnerctl, "require_root"),
            mock.patch.object(
                self.runnerctl,
                "check_prerequisites",
                side_effect=self.runnerctl.RunnerError("not ready"),
            ),
            mock.patch.object(self.runnerctl, "ensure_account") as ensure_account,
            self.assertRaisesRegex(self.runnerctl.RunnerError, "not ready"),
        ):
            self.runnerctl.reconcile(instance, self.platform)

        ensure_account.assert_not_called()

    def test_manager_mounts_socket_but_job_configuration_does_not(self) -> None:
        instance = self.instances["frontend"]
        manager = self.runnerctl.render_service(instance, self.platform)
        job = self.runnerctl.render_registration_template(instance)
        self.assertIn("podman.sock:/run/podman/podman.sock:rw", manager)
        self.assertNotIn("podman.sock:/run/podman/podman.sock:rw", job)
        self.assertIn("--network host", manager)
        self.assertIn(
            "  --dns 100.100.100.100 \\\n  docker.io/gitlab/gitlab-runner:v18.10.1 \\",
            manager,
        )
        self.assertNotIn("\n+", manager)
        self.assertIn('volumes = ["/cache"]', job)

    def test_service_account_rejects_supplementary_host_roles(self) -> None:
        instance = self.instances["frontend"]
        entry = self.runnerctl.pwd.struct_passwd(
            (
                instance["account"]["user"],
                "x",
                instance["account"]["uid"],
                1001,
                "",
                instance["account"]["home"],
                "/bin/bash",
            )
        )
        primary_group = self.runnerctl.grp.struct_group(
            (instance["account"]["user"], "x", 1001, [])
        )
        with (
            mock.patch.object(self.runnerctl.pwd, "getpwnam", return_value=entry),
            mock.patch.object(self.runnerctl.grp, "getgrgid", return_value=primary_group),
            mock.patch.object(self.runnerctl.os, "getgrouplist", return_value=[1001, 998]),
            self.assertRaisesRegex(self.runnerctl.RunnerError, "supplementary"),
        ):
            self.runnerctl.ensure_account(instance, self.platform)

    def test_run_as_clears_the_parent_environment(self) -> None:
        instance = self.instances["frontend"]
        entry = self.runnerctl.pwd.struct_passwd(
            (
                instance["account"]["user"],
                "x",
                instance["account"]["uid"],
                1001,
                "",
                instance["account"]["home"],
                "/bin/bash",
            )
        )
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(self.runnerctl, "run", return_value=completed) as invoked:
            self.runnerctl.run_as(
                entry,
                [self.platform["podman"], "info"],
                platform=self.platform,
            )

        arguments = invoked.call_args.args[0]
        self.assertIn("--ignore-environment", arguments)
        self.assertIn("PATH=/usr/bin", arguments)

    def test_atomic_write_preserves_an_unchanged_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "managed"
            path.write_text("desired\n")
            path.chmod(0o600)
            before = path.stat()

            changed = self.runnerctl.atomic_write(
                path,
                "desired\n",
                mode=0o600,
                uid=os.getuid(),
                gid=os.getgid(),
            )

            self.assertFalse(changed)
            self.assertEqual(before.st_ino, path.stat().st_ino)

    def test_ca_trust_refresh_is_retried_after_files_already_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            certificate = root / "public.crt"
            certificate.write_text("public certificate fixture\n")
            instance = copy.deepcopy(self.instances["frontend"])
            instance["gitlab"]["caCertificate"] = str(certificate)
            entry = self.runnerctl.pwd.struct_passwd(
                ("fixture", "x", os.getuid(), os.getgid(), "", str(root), "/bin/bash")
            )
            platform = {
                **self.platform,
                "caAnchorDirectory": str(root / "anchors"),
                "containerCertsDirectory": str(root / "registry"),
            }
            write = self.runnerctl.atomic_write

            def write_as_test_user(path, content, **kwargs):
                return write(path, content, **{**kwargs, "uid": os.getuid(), "gid": os.getgid()})

            with (
                mock.patch.object(self.runnerctl.os, "fchown"),
                mock.patch.object(self.runnerctl, "atomic_write", side_effect=write_as_test_user),
                mock.patch.object(
                    self.runnerctl,
                    "run",
                    side_effect=[
                        self.runnerctl.RunnerError("trust failed"),
                        subprocess.CompletedProcess([], 0),
                    ],
                ) as invoked,
            ):
                with self.assertRaisesRegex(self.runnerctl.RunnerError, "trust failed"):
                    self.runnerctl.reconcile_ca(instance, entry, config, platform)
                self.assertTrue((config / ".trust.pending").exists())
                self.runnerctl.reconcile_ca(instance, entry, config, platform)
                self.assertFalse((config / ".trust.pending").exists())
                self.assertEqual(invoked.call_count, 2)

    def test_atomic_write_removes_a_temporary_file_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "managed"
            with (
                mock.patch.object(
                    self.runnerctl.os,
                    "replace",
                    side_effect=OSError("simulated replacement failure"),
                ),
                self.assertRaises(OSError),
            ):
                self.runnerctl.atomic_write(
                    path,
                    "sensitive test value\n",
                    mode=0o600,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            self.assertEqual(list(root.iterdir()), [])

    def test_registration_passes_only_an_allowlisted_environment(self) -> None:
        instance = self.instances["frontend"]
        authentication_value = "".join(("gl", "rt-", "test-only-value"))
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config_directory = home / "gitlab-runner/config"
            config_directory.mkdir(parents=True)
            entry = self.runnerctl.pwd.struct_passwd(
                (
                    instance["account"]["user"],
                    "x",
                    os.getuid(),
                    os.getgid(),
                    "",
                    str(home),
                    "/bin/bash",
                )
            )
            completed = subprocess.CompletedProcess([], 0)
            rendered = StringIO()
            with (
                redirect_stderr(rendered),
                mock.patch.dict(
                    os.environ,
                    {
                        "GITLAB_RUNNER_TOKEN": authentication_value,
                        "UNRELATED_SECRET": "must-not-cross-the-boundary",
                    },
                    clear=True,
                ),
                mock.patch.object(self.runnerctl, "require_root"),
                mock.patch.object(self.runnerctl.pwd, "getpwnam", return_value=entry),
                mock.patch.object(
                    self.runnerctl.subprocess, "run", return_value=completed
                ) as invoked,
                mock.patch.object(self.runnerctl, "reconcile"),
                mock.patch.object(self.runnerctl, "verify"),
            ):
                self.runnerctl.register(instance, self.platform)

            arguments = invoked.call_args.args[0]
            environment = invoked.call_args.kwargs["env"]
            self.assertNotIn(authentication_value, arguments)
            self.assertEqual(environment["CI_SERVER_TOKEN"], authentication_value)
            self.assertNotIn("UNRELATED_SECRET", environment)
            self.assertIn("[done] Registering Runner", rendered.getvalue())
            self.assertNotIn(authentication_value, rendered.getvalue())

    def test_manager_inspection_rejects_runtime_drift(self):
        instance = self.instances["frontend"]
        uid = instance["account"]["uid"]
        state = {
            "running": True,
            "network": "host",
            "privileged": False,
            "image": "fixture-image",
            "mounts": [
                {
                    "Type": "bind",
                    "Source": source,
                    "Destination": destination,
                    "RW": True,
                }
                for destination, source in {
                    "/etc/gitlab-runner": instance["account"]["home"] + "/gitlab-runner/config",
                    "/cache": instance["account"]["home"] + "/gitlab-runner/cache",
                    "/run/podman/podman.sock": f"/run/user/{uid}/podman/podman.sock",
                }.items()
            ],
        }
        self.assertTrue(self.runnerctl.manager_matches(instance, uid, state, "fixture-image"))
        for change in (
            {"running": False},
            {"network": "bridge"},
            {"privileged": True},
            {"image": "other"},
            {"mounts": []},
            {"mounts": state["mounts"] + [state["mounts"][0]]},
        ):
            self.assertFalse(
                self.runnerctl.manager_matches(instance, uid, state | change, "fixture-image")
            )
        state["mounts"][2]["Source"] = "/run/user/999/podman/podman.sock"
        self.assertFalse(self.runnerctl.manager_matches(instance, uid, state, "fixture-image"))
        self.assertFalse(self.runnerctl.manager_matches(instance, uid, [], "fixture-image"))

    def test_existing_account_requires_locked_password(self):
        instance = self.instances["frontend"]
        account = instance["account"]
        entry = self.runnerctl.pwd.struct_passwd(
            (
                account["user"],
                "x",
                account["uid"],
                1001,
                "",
                account["home"],
                "/bin/bash",
            )
        )
        primary = self.runnerctl.grp.struct_group((account["user"], "x", 1001, []))
        for state in ("L", "P", "NP"):
            with (
                mock.patch.object(self.runnerctl.pwd, "getpwnam", return_value=entry),
                mock.patch.object(self.runnerctl.grp, "getgrgid", return_value=primary),
                mock.patch.object(self.runnerctl.os, "getgrouplist", return_value=[1001]),
                mock.patch.object(
                    self.runnerctl,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, f"{account['user']} {state} fixture"
                    ),
                ),
            ):
                if state == "L":
                    self.assertEqual(
                        self.runnerctl.ensure_account(instance, self.platform),
                        entry,
                    )
                else:
                    with self.assertRaisesRegex(self.runnerctl.RunnerError, "locked password"):
                        self.runnerctl.ensure_account(instance, self.platform)

    def test_job_network_is_removed_when_validation_fails(self) -> None:
        instance = self.instances["frontend"]
        entry = self.runnerctl.pwd.struct_passwd(
            (
                instance["account"]["user"],
                "x",
                os.getuid(),
                os.getgid(),
                "",
                instance["account"]["home"],
                "/bin/bash",
            )
        )
        completed = subprocess.CompletedProcess([], 0, "", "")
        with (
            mock.patch.object(
                self.runnerctl,
                "run_as",
                side_effect=[
                    completed,
                    self.runnerctl.RunnerError("job failed"),
                    completed,
                ],
            ) as invoked,
            self.assertRaisesRegex(self.runnerctl.RunnerError, "job failed"),
        ):
            self.runnerctl.validate_job_network(
                instance,
                self.platform,
                entry,
            )

        cleanup_arguments = invoked.call_args_list[-1].args[1]
        self.assertEqual(
            cleanup_arguments[1:5], ["network", "rm", "--force", cleanup_arguments[-1]]
        )


class ReconcileTests(unittest.TestCase):
    """Reconcile against a fake host: idempotence, retry and drift handling."""

    STAGES = (
        "Checking prerequisites",
        "Preparing account, sub-IDs and runtime",
        "Reconciling trust and configuration",
        "Preparing manager image",
        "Converging Runner service",
    )

    def setUp(self) -> None:
        self.instance = copy.deepcopy(load_instances(INSTANCE_FILES)["frontend"])
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.entry = operations.pwd.struct_passwd(
            (
                self.instance["account"]["user"],
                "x",
                os.getuid(),
                os.getgid(),
                "",
                str(self.root),
                "/bin/bash",
            )
        )
        self.paths = operations.HostPaths(
            self.root / "subuid", self.root / "subgid", self.root / "run"
        )
        bus = self.paths.runtime / str(self.entry.pw_uid) / "bus"
        bus.parent.mkdir(parents=True)
        bus.touch()
        self.platform = {
            **PLATFORMS["arch"],
            "caAnchorDirectory": str(self.root / "anchors"),
            "containerCertsDirectory": str(self.root / "certs"),
        }
        self.calls: list[list[str]] = []
        self.active = False
        self.image_present = False
        self.fail_restart = False
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name in ("require_root", "check_prerequisites", "verify_rootless_podman"):
            stack.enter_context(mock.patch.object(operations, name))
        stack.enter_context(mock.patch.object(operations, "inspect_policy", return_value=[]))
        stack.enter_context(
            mock.patch.object(operations, "ensure_account", return_value=self.entry)
        )
        stack.enter_context(
            mock.patch.object(operations, "ensure_subordinate_range", side_effect=self.allocate)
        )
        self.native_run = stack.enter_context(
            mock.patch.object(operations, "run", return_value=subprocess.CompletedProcess([], 0))
        )
        stack.enter_context(mock.patch.object(operations, "run_as", side_effect=self.run_as))
        self.inspect = stack.enter_context(
            mock.patch.object(operations, "inspect_manager", return_value="matches-declaration")
        )

    def allocate(
        self, path: Path, user: str, desired: dict[str, int], *, aliases: tuple[str, ...] = ()
    ) -> None:
        self.assertTrue(path.is_relative_to(self.root))
        ensure_subordinate_range(
            path, user, desired, uid=os.getuid(), gid=os.getgid(), aliases=aliases
        )

    def run_as(self, _entry, command, **_kwargs):
        self.calls.append(command)
        if command[1:3] == ["image", "exists"]:
            return subprocess.CompletedProcess(command, 0 if self.image_present else 1)
        if command[1:2] == ["pull"]:
            self.image_present = True
        if "is-active" in command:
            return subprocess.CompletedProcess(command, 0 if self.active else 3)
        if "restart" in command and self.fail_restart:
            raise operations.RunnerError("restart failed")
        if "start" in command or "restart" in command:
            self.active = True
        return subprocess.CompletedProcess(command, 0)

    def reconcile(self) -> bool:
        return operations.reconcile(self.instance, self.platform, paths=self.paths)

    @property
    def pending(self) -> Path:
        return self.root / "gitlab-runner/config/.reconcile.pending"

    def restarted(self) -> bool:
        return any("restart" in call for call in self.calls)

    def change_memory(self) -> None:
        self.instance["runner"]["memory"] = "8g"
        artifacts = self.instance["artifacts"]
        artifacts["registrationTemplate"] = artifacts["registrationTemplate"].replace(
            'memory = "4g"', 'memory = "8g"'
        )

    def test_numeric_alias_conflict_stops_reconcile_before_native_changes(self) -> None:
        allocations = (
            (self.paths.subuid, self.instance["account"]["subUid"]),
            (self.paths.subgid, self.instance["account"]["subGid"]),
        )
        for target, _ in allocations:
            with self.subTest(target=target):
                for path, allocation in allocations:
                    path.write_text(
                        f"{self.entry.pw_name}:{allocation['start']}:{allocation['count']}\n"
                    )
                target.write_text(target.read_text() + f"{self.entry.pw_uid}:300000:65536\n")
                before = {path: path.read_bytes() for path, _ in allocations}
                self.calls.clear()
                self.native_run.reset_mock()
                with redirect_stderr(StringIO()), self.assertRaises(operations.RunnerError):
                    self.reconcile()
                self.assertEqual({path: path.read_bytes() for path, _ in allocations}, before)
                self.native_run.assert_not_called()
                self.assertEqual(self.calls, [])
                self.assertFalse(self.pending.exists())

    def test_first_reconcile_reports_every_stage(self) -> None:
        rendered = StringIO()
        with redirect_stderr(rendered):
            self.assertTrue(self.reconcile())
        for stage in self.STAGES:
            self.assertIn(stage, rendered.getvalue())

    def test_second_reconcile_changes_nothing(self) -> None:
        with redirect_stderr(StringIO()):
            self.reconcile()
        files = [path for path in self.root.rglob("*") if path.is_file()]
        before = {path: path.stat().st_ino for path in files}
        self.calls.clear()
        with redirect_stderr(StringIO()):
            self.assertFalse(self.reconcile())
        self.assertEqual(before, {path: path.stat().st_ino for path in files})
        mutating = ("restart", "pull", "daemon-reload")
        self.assertFalse(any(word in call for call in self.calls for word in mutating))

    def test_failed_restart_keeps_pending_and_the_next_run_retries(self) -> None:
        with redirect_stderr(StringIO()):
            self.reconcile()
        self.change_memory()
        self.fail_restart = True
        failure = StringIO()
        with (
            redirect_stderr(failure),
            self.assertRaisesRegex(operations.RunnerError, "restart failed"),
        ):
            self.reconcile()
        self.assertIn("[failed] Converging Runner service", failure.getvalue())
        self.assertNotIn("[done] Converging Runner service", failure.getvalue())
        self.assertTrue(self.pending.exists())
        self.fail_restart = False
        with redirect_stderr(StringIO()):
            self.assertTrue(self.reconcile())
            self.assertFalse(self.pending.exists())
            self.assertFalse(self.reconcile())

    def test_manager_drift_forces_a_restart_until_it_succeeds(self) -> None:
        with redirect_stderr(StringIO()):
            self.reconcile()
        self.inspect.return_value = "drifted"
        self.fail_restart = True
        with (
            redirect_stderr(StringIO()),
            self.assertRaisesRegex(operations.RunnerError, "restart failed"),
        ):
            self.reconcile()
        self.assertTrue(self.pending.exists())
        self.fail_restart = False
        self.calls.clear()
        with redirect_stderr(StringIO()):
            self.assertTrue(self.reconcile())
        self.assertTrue(self.restarted())
        self.inspect.return_value = "matches-declaration"
        with redirect_stderr(StringIO()):
            self.assertFalse(self.reconcile())


class RunnerStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.instance = load_instances(INSTANCE_FILES)["frontend"]
        account = self.instance["account"]
        self.entry = operations.pwd.struct_passwd(
            (account["user"], "x", account["uid"], account["uid"], "", str(self.root), "/bin/bash")
        )
        self.paths = operations.HostPaths(
            self.root / "subuid", self.root / "subgid", self.root / "runtime"
        )
        for path, allocation in (
            (self.paths.subuid, account["subUid"]),
            (self.paths.subgid, account["subGid"]),
        ):
            path.write_text(f"{account['user']}:{allocation['start']}:{allocation['count']}\n")
        self.socket_path = self.paths.runtime / str(self.entry.pw_uid) / "podman/podman.sock"
        self.socket_path.parent.mkdir(parents=True)
        podman_socket = socket.socket(socket.AF_UNIX)
        self.addCleanup(podman_socket.close)
        podman_socket.bind(str(self.socket_path))
        self.registration = self.root / "gitlab-runner/config/config.toml"
        self.registration.parent.mkdir(parents=True)
        self.secret = "fixture-only-registration-value"
        self.registration.write_text(f'[[runners]]\ntoken = "{self.secret}"\n')
        self.service_state = "active"
        self.container_missing = False
        self.manager_state = {
            "running": True,
            "network": "host",
            "privileged": False,
            "image": "fixture-image",
            "mounts": [
                {"Type": "bind", "Source": source, "Destination": target, "RW": True}
                for target, source in {
                    "/etc/gitlab-runner": account["home"] + "/gitlab-runner/config",
                    "/cache": account["home"] + "/gitlab-runner/cache",
                    "/run/podman/podman.sock": f"/run/user/{self.entry.pw_uid}/podman/podman.sock",
                }.items()
            ],
        }
        self.native_calls = []
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(operations.os, "geteuid", return_value=0))
        self.account_lookup = stack.enter_context(
            mock.patch.object(operations.pwd, "getpwnam", return_value=self.entry)
        )
        stack.enter_context(mock.patch.object(operations, "DEFAULT_PATHS", self.paths))
        stack.enter_context(
            mock.patch.object(operations.subprocess, "run", side_effect=self.native)
        )
        for name in ("reconcile", "register", "verify", "operation_lock"):
            stack.enter_context(
                mock.patch.object(operations, name, side_effect=AssertionError("mutation"))
            )
        read_text = Path.read_text

        def fixture_read(path, *args, **kwargs):
            if not (path.is_relative_to(self.root) or path.is_relative_to(FIXTURES)):
                raise AssertionError("status read outside isolated fixtures")
            return read_text(path, *args, **kwargs)

        stack.enter_context(
            mock.patch.object(Path, "read_text", autospec=True, side_effect=fixture_read)
        )

    def native(self, argv, **kwargs):
        self.native_calls.append(argv)
        platform = PLATFORMS["arch"]
        if platform["systemctl"] in argv:
            self.assertIn("is-active", argv)
            environment = kwargs["env"]
            self.assertEqual(environment["XDG_RUNTIME_DIR"], str(self.socket_path.parents[1]))
            code = 0 if self.service_state == "active" else 3
            return subprocess.CompletedProcess(argv, code, self.service_state + "\n")
        if platform["podman"] in argv:
            command = argv[argv.index(platform["podman"]) + 1 :]
            if command[0] == "inspect":
                return subprocess.CompletedProcess(
                    argv, int(self.container_missing), json.dumps(self.manager_state)
                )
            if command[:2] == ["image", "inspect"]:
                return subprocess.CompletedProcess(argv, 0, "fixture-image\n")
        raise AssertionError("unexpected native command")

    def inspect(self):
        stdout, stderr = StringIO(), StringIO()
        arguments = [
            "runnerctl",
            "--platform",
            "arch",
            "-c",
            str(INSTANCE_FILES[0]),
            "status",
            "frontend",
        ]
        with (
            mock.patch.object(sys, "argv", arguments),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as exited,
        ):
            cli.main_cli()
        self.assertEqual(exited.exception.code, 0, stderr.getvalue())
        self.assertNotIn(self.secret, stdout.getvalue() + stderr.getvalue())
        line = stdout.getvalue().strip()
        name, fields = line.split(": ", 1)
        self.assertEqual(name, "frontend")
        return dict(field.split("=", 1) for field in fields.split(", "))

    def test_cli_reports_healthy_isolated_state(self) -> None:
        self.assertEqual(
            self.inspect(),
            {
                "account": "present",
                "subids": "ok",
                "socket": "present",
                "service": "active",
                "container": "matches-declaration",
                "registration": "present",
            },
        )

    def test_missing_account_skips_all_native_probes(self) -> None:
        self.account_lookup.side_effect = KeyError("fixture-account")
        self.assertEqual(
            self.inspect(),
            {
                "account": "missing",
                "subids": "missing",
                "socket": "missing",
                "service": "unavailable",
                "container": "absent",
                "registration": "absent",
            },
        )
        self.assertEqual(self.native_calls, [])

    def test_cli_reports_drift_in_either_subordinate_allocation(self) -> None:
        for path in (self.paths.subuid, self.paths.subgid):
            with self.subTest(path=path):
                declared = path.read_text()
                path.write_text("fixture-other-account:1:65536\n")
                self.assertEqual(self.inspect()["subids"], "drifted")
                path.write_text(declared)

    def test_duplicate_account_allocations_report_drift_without_writes(self) -> None:
        for path in (self.paths.subuid, self.paths.subgid):
            declared = path.read_text()
            with self.subTest(path=path):
                path.write_text(declared + f"{self.entry.pw_name}:300000:65536\n")
                before = path.read_bytes()
                self.assertEqual(self.inspect()["subids"], "drifted")
                self.assertEqual(path.read_bytes(), before)
                path.write_text(declared)

    def test_numeric_owner_aliases_share_account_identity_in_both_files(self) -> None:
        fields = list(self.entry)
        fields[3] += 7
        self.entry = operations.pwd.struct_passwd(fields)
        self.account_lookup.return_value = self.entry
        for path in (self.paths.subuid, self.paths.subgid):
            declared = path.read_text()
            with self.subTest(path=path):
                path.write_text(declared + f"{self.entry.pw_uid}:300000:65536\n")
                before = path.read_bytes()
                self.assertEqual(self.inspect()["subids"], "drifted")
                self.assertEqual(path.read_bytes(), before)
                path.write_text(declared.replace(self.entry.pw_name, str(self.entry.pw_uid)))
                self.assertEqual(self.inspect()["subids"], "ok")
                path.write_text(declared)

    def test_missing_and_regular_socket_paths_report_missing(self) -> None:
        self.socket_path.unlink()
        self.assertEqual(self.inspect()["socket"], "missing")
        self.socket_path.touch()
        self.assertEqual(self.inspect()["socket"], "missing")

    def test_cli_reports_inactive_and_unavailable_services(self) -> None:
        for state, expected in (("inactive", "inactive"), ("", "unavailable")):
            with self.subTest(state=state):
                self.service_state = state
                self.assertEqual(self.inspect()["service"], expected)

    def test_cli_reports_drifted_and_missing_manager(self) -> None:
        self.manager_state["image"] = "unexpected-image"
        self.assertEqual(self.inspect()["container"], "drifted")
        self.container_missing = True
        self.assertEqual(self.inspect()["container"], "absent")

    def test_cli_reports_absent_and_invalid_registration_without_values(self) -> None:
        for content, expected in (
            ("", "absent"),
            ("[[runners]]\ntoken = 7\n", "invalid"),
            (f'[[runners]]\ntoken = "{self.secret}', "invalid"),
        ):
            with self.subTest(expected=expected):
                self.registration.write_text(content)
                self.assertEqual(self.inspect()["registration"], expected)


if __name__ == "__main__":
    unittest.main()
