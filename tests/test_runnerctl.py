#!/usr/bin/env python3

from __future__ import annotations

import copy
from contextlib import ExitStack
from contextlib import redirect_stderr
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


RUNNERCTL_PATH = Path(__file__).resolve().parents[1] / "runnerctl.py"
CONFIG_PATH = Path(__file__).parent / "runner-test-config.json"

for arg in list(sys.argv):
    if arg.endswith(".json") and Path(arg).exists():
        CONFIG_PATH = Path(arg)
        sys.argv.remove(arg)
    elif arg.endswith("runnerctl.py") and Path(arg).exists():
        RUNNERCTL_PATH = Path(arg)
        sys.argv.remove(arg)


def load_runnerctl(path: Path | None = None):
    try:
        import runnerctl

        return runnerctl
    except ImportError:
        pass
    if path is not None and path.exists():
        model_path = path.parent / "runner_model.py"
        model_spec = importlib.util.spec_from_file_location("runner_model", model_path)
        if model_spec and model_spec.loader:
            model_module = importlib.util.module_from_spec(model_spec)
            sys.modules["runner_model"] = model_module
            model_spec.loader.exec_module(model_module)

        spec = importlib.util.spec_from_file_location("runnerctl", path)
        if spec is not None and spec.loader is not None:
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
    raise RuntimeError("unable to load runnerctl")


class RunnerControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runnerctl = load_runnerctl(RUNNERCTL_PATH)
        cls.document = json.loads(CONFIG_PATH.read_text())
        cls.instances = cls.document["instances"]

    def test_host_configuration_is_valid(self) -> None:
        self.runnerctl.validate_instances(self.instances)

    def test_empty_configuration_is_valid(self) -> None:
        self.runnerctl.validate_instances({})

    def test_shared_declaration_cases(self) -> None:
        cases = json.loads(Path(__file__).with_name("validation-cases.json").read_text())
        for case in cases:
            with self.subTest(case=case):
                instance = copy.deepcopy(self.instances["frontend"])
                value = instance
                for key in case["path"][:-1]:
                    value = value[key]
                value[case["path"][-1]] = case["value"]
                if case["valid"]:
                    self.runnerctl.validate_instances({"frontend": instance})
                else:
                    with self.assertRaises(self.runnerctl.RunnerError):
                        self.runnerctl.validate_instances({"frontend": instance})

    def test_operation_lock_serializes_instances(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner.lock"
            with self.runnerctl.operation_lock(path):
                with self.assertRaisesRegex(self.runnerctl.RunnerError, "another Runner"):
                    with self.runnerctl.operation_lock(path):
                        self.fail("acquired twice")
            with self.runnerctl.operation_lock(path):
                pass

    def test_timeout_does_not_echo_arguments_or_output(self) -> None:
        with mock.patch.object(
            self.runnerctl.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["fake", "private"], 1, output="private"),
        ):
            with self.assertRaises(self.runnerctl.RunnerError) as raised:
                self.runnerctl.run(["fake", "private"], timeout=1)
        self.assertNotIn("private", str(raised.exception))

    def test_reconcile_twice_change_and_failed_restart_retry(self) -> None:
        instance = copy.deepcopy(self.instances["frontend"])
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            entry = self.runnerctl.pwd.struct_passwd(
                (
                    instance["account"]["user"],
                    "x",
                    os.getuid(),
                    os.getgid(),
                    "",
                    str(root),
                    "/bin/bash",
                )
            )
            paths = self.runnerctl.HostPaths(root / "subuid", root / "subgid", root / "run")
            bus = paths.runtime / str(entry.pw_uid) / "bus"
            bus.parent.mkdir(parents=True)
            bus.touch()
            platform = {
                **self.document["platform"],
                "caAnchorDirectory": str(root / "anchors"),
                "containerCertsDirectory": str(root / "certs"),
            }
            calls = []
            active = False
            image_present = False
            fail_restart = False

            def run_as(entry, command, **kwargs):
                nonlocal active, image_present
                calls.append(command)
                if command[1:3] == ["image", "exists"]:
                    return subprocess.CompletedProcess(command, 0 if image_present else 1)
                if command[1:2] == ["pull"]:
                    image_present = True
                if "is-active" in command:
                    return subprocess.CompletedProcess(command, 0 if active else 3)
                if "restart" in command and fail_restart:
                    raise self.runnerctl.RunnerError("restart failed")
                if "start" in command or "restart" in command:
                    active = True
                return subprocess.CompletedProcess(command, 0)

            for name in (
                "require_root",
                "check_prerequisites",
                "verify_rootless_podman",
            ):
                stack.enter_context(mock.patch.object(self.runnerctl, name))
            stack.enter_context(
                mock.patch.object(self.runnerctl, "ensure_account", return_value=entry)
            )

            # Native allocation ownership is tested separately; here the private
            # adapter keeps its simulated allocations inside this instance HOME.
            def allocation(path, user, desired):
                self.assertTrue(path.is_relative_to(root))
                self.runnerctl.atomic_write(
                    path,
                    f"{user}:{desired['start']}:{desired['count']}\n",
                    mode=0o644,
                    uid=os.getuid(),
                    gid=os.getgid(),
                )

            stack.enter_context(
                mock.patch.object(
                    self.runnerctl, "ensure_subordinate_range", side_effect=allocation
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.runnerctl,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0),
                )
            )
            stack.enter_context(mock.patch.object(self.runnerctl, "run_as", side_effect=run_as))
            inspect = stack.enter_context(
                mock.patch.object(
                    self.runnerctl,
                    "inspect_manager",
                    return_value="matches-declaration",
                )
            )
            rendered = StringIO()
            with redirect_stderr(rendered):
                self.assertTrue(self.runnerctl.reconcile(instance, platform, paths=paths))
            for label in (
                "Checking prerequisites",
                "Preparing account, sub-IDs and runtime",
                "Reconciling trust and configuration",
                "Preparing manager image",
                "Converging Runner service",
            ):
                self.assertIn(label, rendered.getvalue())
            files = [path for path in root.rglob("*") if path.is_file()]
            before = {path: path.stat().st_ino for path in files}
            calls.clear()
            self.assertFalse(self.runnerctl.reconcile(instance, platform, paths=paths))
            self.assertEqual(before, {path: path.stat().st_ino for path in files})
            self.assertFalse(
                any(
                    "restart" in call or "pull" in call or "daemon-reload" in call for call in calls
                )
            )
            instance["runner"]["memory"] = "8g"
            instance["artifacts"]["registrationTemplate"] = instance["artifacts"][
                "registrationTemplate"
            ].replace('memory = "4g"', 'memory = "8g"')
            fail_restart = True
            failure_output = StringIO()
            with redirect_stderr(failure_output):
                with self.assertRaisesRegex(self.runnerctl.RunnerError, "restart failed"):
                    self.runnerctl.reconcile(instance, platform, paths=paths)
            self.assertIn("[failed] Converging Runner service", failure_output.getvalue())
            self.assertNotIn("[done] Converging Runner service", failure_output.getvalue())
            self.assertTrue((root / "gitlab-runner/config/.reconcile.pending").exists())
            fail_restart = False
            self.assertTrue(self.runnerctl.reconcile(instance, platform, paths=paths))
            self.assertFalse((root / "gitlab-runner/config/.reconcile.pending").exists())
            self.assertFalse(self.runnerctl.reconcile(instance, platform, paths=paths))
            inspect.return_value = "drifted"
            fail_restart = True
            with self.assertRaisesRegex(self.runnerctl.RunnerError, "restart failed"):
                self.runnerctl.reconcile(instance, platform, paths=paths)
            self.assertTrue((root / "gitlab-runner/config/.reconcile.pending").exists())
            fail_restart = False
            calls.clear()
            self.assertTrue(self.runnerctl.reconcile(instance, platform, paths=paths))
            self.assertTrue(any("restart" in call for call in calls))
            inspect.return_value = "matches-declaration"
            self.assertFalse(self.runnerctl.reconcile(instance, platform, paths=paths))

    def test_cli_exposes_the_arch_runner_lifecycle_without_token_arguments(
        self,
    ) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(RUNNERCTL_PATH),
                "--config",
                str(CONFIG_PATH),
                "--help",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )

        for command in (
            "check",
            "reconcile",
            "register",
            "status",
            "validate",
            "verify",
        ):
            self.assertIn(command, result.stdout)
        self.assertNotIn("--token", result.stdout)

    def test_progress_boundaries_use_static_labels_and_mark_failures(self) -> None:
        output = StringIO()
        instance = self.instances["frontend"]
        platform = self.document["platform"]
        with redirect_stderr(output):
            with mock.patch.object(
                self.runnerctl,
                "check_prerequisites",
                side_effect=self.runnerctl.RunnerError("synthetic secret"),
            ):
                with self.assertRaises(self.runnerctl.RunnerError):
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
            self.runnerctl.validate_instances(instances)

    def test_short_subordinate_id_ranges_are_rejected(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["account"]["subUid"]["count"] = 65535
        with self.assertRaisesRegex(self.runnerctl.RunnerError, "at least 65536"):
            self.runnerctl.validate_instances(instances)

    def test_gitlab_health_url_must_use_the_coordinator_hostname(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["gitlab"]["healthUrl"] = "https://other.example/health"
        with self.assertRaisesRegex(self.runnerctl.RunnerError, "same HTTPS hostname"):
            self.runnerctl.validate_instances(instances)

    def test_default_job_image_must_match_the_allowlist(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["runner"]["allowedImages"] = ["docker.io/library/python:*"]
        with self.assertRaisesRegex(self.runnerctl.RunnerError, "match allowedImages"):
            self.runnerctl.validate_instances(instances)

    def test_required_interface_is_optional_and_not_vpn_specific(self) -> None:
        instances = copy.deepcopy(self.instances)
        instances["frontend"]["network"]["requiredInterface"] = None
        self.runnerctl.validate_instances(instances)
        self.assertNotIn("vpn", json.dumps(instances).lower())

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
        ):
            with self.assertRaisesRegex(self.runnerctl.RunnerError, "not ready"):
                self.runnerctl.reconcile(instance, self.document["platform"])

        ensure_account.assert_not_called()

    def test_manager_mounts_socket_but_job_configuration_does_not(self) -> None:
        instance = self.instances["frontend"]
        manager = self.runnerctl.render_service(instance)
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
        ):
            with self.assertRaisesRegex(self.runnerctl.RunnerError, "supplementary"):
                self.runnerctl.ensure_account(instance, self.document["platform"])

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
                [self.document["platform"]["podman"], "info"],
                platform=self.document["platform"],
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
                **self.document["platform"],
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
            with mock.patch.object(
                self.runnerctl.os,
                "replace",
                side_effect=OSError("simulated replacement failure"),
            ):
                with self.assertRaises(OSError):
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
                self.runnerctl.register(instance, self.document["platform"])

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
                        self.runnerctl.ensure_account(instance, self.document["platform"]),
                        entry,
                    )
                else:
                    with self.assertRaisesRegex(self.runnerctl.RunnerError, "locked password"):
                        self.runnerctl.ensure_account(instance, self.document["platform"])

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
        with mock.patch.object(
            self.runnerctl,
            "run_as",
            side_effect=[
                completed,
                self.runnerctl.RunnerError("job failed"),
                completed,
            ],
        ) as invoked:
            with self.assertRaisesRegex(self.runnerctl.RunnerError, "job failed"):
                self.runnerctl.validate_job_network(
                    instance,
                    self.document["platform"],
                    entry,
                )

        cleanup_arguments = invoked.call_args_list[-1].args[1]
        self.assertEqual(
            cleanup_arguments[1:5], ["network", "rm", "--force", cleanup_arguments[-1]]
        )


if __name__ == "__main__":
    unittest.main()
