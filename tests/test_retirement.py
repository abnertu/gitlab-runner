# pyright: standard
"""Exercise locked retirement with synthetic storage, units and native boundaries."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import tomllib
import unittest
from contextlib import closing, contextmanager
from pathlib import Path
from unittest import mock

import test_inspection as support

from runnerctl import inspection, operations, retirement
from runnerctl.config import load_instances


class RetirementCliTests(unittest.TestCase):
    def setUp(self):
        self.f = support.InspectionCliTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.ready()
        self.database()
        for path in (
            self.f.home / ".local/share/containers/storage/libpod",
            self.f.home / ".local/share/containers/storage/overlay",
            self.f.paths.runtime / str(self.f.uid) / "containers",
            self.f.paths.runtime / str(self.f.uid) / "libpod/tmp",
        ):
            self.f.owned(path)
        self.f.owned(self.f.paths.runtime / str(self.f.uid) / "libpod/tmp/alive", b"", 0o600)
        self.f.owned(self.f.paths.proc_root / "4242")
        self.f.owned(self.f.paths.proc_root / "4242/fd")
        (self.f.paths.proc_root / "4242/fd/5").symlink_to(
            self.f.home / ".local/share/containers/storage/db.sql"
        )
        self.f.lock_path.touch(mode=0o600)
        self.system_ownership()
        self.unit = self.f.unit
        self.name = self.f.instance["runner"]["serviceName"]
        self.links = [
            self.unit.parent / "default.target.wants" / self.unit.name,
            self.unit.parent / "sockets.target.wants/podman.socket",
        ]
        for link, target in zip(
            self.links, [str(self.unit), self.f.platform["podmanSocketUnit"]], strict=True
        ):
            self.f.owned(link.parent)
            link.symlink_to(target)
            if os.getuid() == 0:
                os.lchown(link, self.f.uid, self.f.gid)
        self.pending = self.f.private.parent / ".purge.pending"
        runtime = self.f.paths.runtime / str(self.f.uid)
        self.f.owned(runtime)
        self.bus = socket.socket(socket.AF_UNIX)
        self.addCleanup(self.bus.close)
        self.bus.bind(str(runtime / "bus"))
        if os.getuid() == 0:
            os.chown(runtime / "bus", self.f.uid, self.f.gid)
        self.active = True
        self.socket_active = True
        self.loaded = True
        self.stale = False
        self.dropins = ""
        self.dropins_after_reload = None
        self.masked_stop = False
        self.exists_error = False
        self.native_failure = None
        self.calls = []
        self.initializations = []
        self.containers = {self.name: True, "previous-stopped": False, "unrelated": True}
        self.manager_patch = mock.patch.object(
            operations, "inspect_manager", return_value="matches-declaration"
        )
        self.manager = self.manager_patch.start()
        self.addCleanup(self.manager_patch.stop)
        native_patch = mock.patch.object(operations, "run_as", side_effect=self.native)
        native_patch.start()
        self.addCleanup(native_patch.stop)
        trust_patch = mock.patch.object(operations, "run", side_effect=self.trust)
        trust_patch.start()
        self.addCleanup(trust_patch.stop)
        self.preserved = self.retained()

    def database(self):
        path = self.f.home / ".local/share/containers/storage/db.sql"
        path.unlink()
        with closing(sqlite3.connect(path)) as database:
            database.execute("CREATE TABLE DBConfig (SchemaVersion INTEGER)")
            database.execute("INSERT INTO DBConfig VALUES (1)")
            database.commit()
        path.chmod(0o600)
        if os.getuid() == 0:
            os.chown(path, self.f.uid, self.f.gid)

    def system_ownership(self):
        self.root_owned = set()
        original_info = inspection.path_info

        def system_info(path):
            info = original_info(path)
            if info is not None and path in self.root_owned:
                fields = list(info)
                fields[4:6] = [0, 0]
                return os.stat_result(fields)
            return info

        self.info_patch = mock.patch.object(inspection, "path_info", side_effect=system_info)
        self.info_patch.start()
        self.addCleanup(self.info_patch.stop)
        original_file = inspection.regular_file

        @contextmanager
        def public_file(parent, name, **kwargs):
            with original_file(parent, name, **kwargs) as (stream, info):
                path = Path(os.readlink(f"/proc/self/fd/{parent}")) / name
                if path in self.root_owned:
                    fields = list(info)
                    fields[4:6] = [0, 0]
                    info = os.stat_result(fields)
                yield stream, info

        file_patch = mock.patch.object(inspection, "regular_file", side_effect=public_file)
        file_patch.start()
        self.addCleanup(file_patch.stop)

    def retained(self):
        snapshots = self.f.snapshot()
        return {
            path: value
            for path, value in snapshots.items()
            if path.startswith(
                (
                    "homes/" + self.f.user + "/.local/",
                    "homes/" + self.f.user + "/gitlab-runner/cache/",
                )
            )
            or path in {str(self.f.private.relative_to(self.f.root)), "subuid", "subgid"}
        }

    def assert_retained(self):
        self.assertEqual(self.retained(), self.preserved)
        self.assertIs(self.containers["previous-stopped"], False)
        self.assertIs(self.containers["unrelated"], True)
        self.assertTrue(self.f.present)

    def properties(self, unit):
        is_service = unit == self.unit.name
        present = self.loaded if is_service else True
        values = {
            "LoadState": "loaded" if present else "not-found",
            "ActiveState": "active"
            if (self.active if is_service else self.socket_active)
            else "inactive",
            "FragmentPath": str(self.unit)
            if is_service and present
            else ""
            if is_service
            else self.f.platform["podmanSocketUnit"],
            "DropInPaths": self.dropins,
            "Names": unit,
            "NeedDaemonReload": "yes" if self.stale else "no",
            "UnitFileState": "enabled"
            if self.links[0 if is_service else 1].is_symlink()
            else "disabled"
            if present
            else "",
        }
        if not is_service:
            values |= {"ExecStopPre": "", "ExecStopPost": ""}
        else:
            values["MainPID"] = "4242" if self.active else "0"
        return values

    def native(
        self, entry, argv, *, platform, capture=False, check=True, public=False, expected=(0,)
    ):
        self.assertEqual(entry.pw_uid, self.f.uid)
        self.assertEqual(platform, self.f.platform)
        args = argv[1:]
        self.calls.append(tuple(args))
        if self.native_failure is not None and self.native_failure(args):
            raise operations.RunnerError("synthetic native retirement failure")
        if argv[0] == platform["systemctl"]:
            self.assertEqual(args[0], "--user")
            command = args[1]
            if command == "show":
                values = self.properties(args[2])
                # Native systemctl omits empty command arrays, even with --all.
                values = {
                    key: value
                    for key, value in values.items()
                    if key not in {"ExecStopPre", "ExecStopPost"} or value
                }
                return subprocess.CompletedProcess(
                    argv, 0, "\n".join(f"{key}={value}" for key, value in values.items()), ""
                )
            self.assertTrue(self.pending.exists(), "intent must precede every native mutation")
            if command == "daemon-reload":
                self.loaded = self.unit.exists()
                self.stale = False
                if self.dropins_after_reload is not None:
                    self.dropins = self.dropins_after_reload
            elif command == "stop" and args[2] == self.unit.name:
                self.active = False
                if not self.masked_stop:
                    self.containers.pop(self.name, None)
            elif command == "stop" and args[2] == "podman.socket":
                self.socket_active = False
            else:
                self.fail(f"unexpected native mutation: {args}")
            return subprocess.CompletedProcess(argv, 0, "", "")
        return self.podman(argv, platform)

    def podman(self, argv, platform):
        environment = {}
        arguments = argv
        if arguments[0] == platform["env"]:
            index = arguments.index(platform["podman"])
            environment = dict(item.split("=", 1) for item in arguments[1:index])
            arguments = arguments[index:]
        self.assertEqual(arguments[0], platform["podman"])
        options, args = {}, arguments[1:]
        while args and args[0] in {"--root", "--runroot", "--tmpdir", "--storage-driver"}:
            options[args[0]], args = args[1], args[2:]
        self.calls[-1] = tuple(args)
        if args == ["--version"]:
            return subprocess.CompletedProcess(argv, 0, "podman version 5.6.0", "")
        # A native configured backend can redirect storage or refresh a cold runtime.
        # Model its destructive refresh so preservation tests require a live, confined engine.
        backend = "boltdb"
        if "CONTAINERS_CONF" in environment:
            engine = tomllib.loads(Path(environment["CONTAINERS_CONF"]).read_text())["engine"]
            backend = engine["database_backend"]
        root = Path(options.get("--root", str(self.f.root / "redirected-storage")))
        runroot = Path(options.get("--runroot", str(self.f.root / "redirected-runroot")))
        temporary = Path(options.get("--tmpdir", str(self.f.root / "redirected-temporary")))
        database = root / ("db.sql" if backend == "sqlite" else "libpod/bolt_state.db")
        if not database.exists() or not runroot.is_dir() or not (temporary / "alive").is_file():
            self.initializations.append((root, runroot, temporary, backend))
            self.containers.pop("previous-stopped", None)
            return subprocess.CompletedProcess(argv, 125, "", "")
        if args[:2] == ["container", "exists"]:
            code = 125 if self.exists_error else 0 if self.name in self.containers else 1
            return subprocess.CompletedProcess(argv, code, "", "")
        if args[:2] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "sha256:fixture-image", "")
        if args[:2] == ["inspect", "--format"] and args[2] != "{{json .State.Running}}":
            account = self.f.instance["account"]
            mounts = [
                {"Source": source, "Destination": destination, "Type": "bind", "RW": True}
                for destination, source in {
                    "/etc/gitlab-runner": account["home"] + "/gitlab-runner/config",
                    "/cache": account["home"] + "/gitlab-runner/cache",
                    "/run/podman/podman.sock": f"/run/user/{self.f.uid}/podman/podman.sock",
                }.items()
            ]
            observed = {
                "running": True,
                "network": "host",
                "privileged": False,
                "mounts": mounts,
                "image": "sha256:fixture-image",
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(observed), "")
        self.assertEqual(args[:3], ["inspect", "--format", "{{json .State.Running}}"])
        self.assertEqual(args[3], self.name)
        return subprocess.CompletedProcess(argv, 0, json.dumps(self.containers[self.name]), "")

    def trust(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        self.assertEqual(argv, [self.f.platform["trust"], "extract-compat"])
        self.assertTrue(self.pending.exists())
        if self.native_failure is not None and self.native_failure(argv):
            raise operations.RunnerError("synthetic trust failure")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def add_certificates(self):
        source = self.f.root / "public.crt"
        source.write_text("fixture public certificate\n")
        self.f.input.write_text(
            self.f.input.read_text() + '\n[gitlab]\nca_certificate = "public.crt"\n'
        )
        self.f.instance = load_instances([self.f.input])["frontend"]
        self.f.ready()
        self.database()
        policies = inspection.public_policy(
            self.f.instance, self.f.platform, self.f.home, self.f.gid
        )
        for name in ("manager_ca", "system_ca", "registry_ca"):
            policy = policies[name]
            self.f.owned(policy.path.parent, mode=0o700 if policy.uid else 0o755)
            self.f.owned(policy.path, policy.content.encode(), policy.mode)
            if policy.uid == 0:
                self.root_owned |= {policy.path, policy.path.parent}
        self.preserved = self.retained()
        return policies

    def test_retire_and_repeat_preserve_registration_storage_and_unrelated_containers(self):
        self.f.invoke("purge")
        self.assertFalse(self.unit.exists())
        self.assertFalse((self.f.private.parent / "registration-template.toml").exists())
        self.assertFalse(any(link.is_symlink() for link in self.links))
        self.assertNotIn(self.name, self.containers)
        self.assertFalse(self.pending.exists())
        self.assert_retained()
        before = self.f.snapshot()
        self.calls.clear()
        output, _ = self.f.invoke("purge")
        self.assertIn("unchanged", output)
        self.assertEqual(self.f.snapshot(), before)
        self.assertFalse(any(call[1:2] in [("stop",), ("daemon-reload",)] for call in self.calls))
        self.assert_retained()

    def test_inactive_service_preserves_named_stopped_container(self):
        self.active = False
        self.containers[self.name] = False
        self.f.invoke("purge")
        self.assertIs(self.containers[self.name], False)
        self.manager.assert_not_called()
        self.assert_retained()

    def test_socket_hooks_and_incomplete_queries_fail_before_retirement_intent(self):
        original = self.properties
        for key in ("ExecStopPre", "ExecStopPost", "LoadState", "FragmentPath"):
            with self.subTest(key=key):

                def invalid(unit, field=key):
                    values = original(unit)
                    if unit == "podman.socket":
                        if field.startswith("Exec"):
                            values[field] = (
                                "{ path=/fixture/stop-hook ; argv[]=/fixture/stop-hook }"
                            )
                        else:
                            values.pop(field)
                    return values

                before = self.f.snapshot()
                with mock.patch.object(self, "properties", side_effect=invalid):
                    self.f.invoke("purge", expected=1)
                self.assertEqual(self.f.snapshot(), before)
                self.assertFalse(self.pending.exists())
                self.assert_retained()
        native = self.native

        def failed_query(entry, argv, **kwargs):
            result = native(entry, argv, **kwargs)
            if argv[1:3] == ["--user", "show"]:
                return subprocess.CompletedProcess(argv, 1, result.stdout, "query failed")
            return result

        before = self.f.snapshot()
        with mock.patch.object(operations, "run_as", side_effect=failed_query):
            self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertFalse(self.pending.exists())
        self.assert_retained()

    def test_legacy_run_directory_cannot_replace_native_runtime_storage(self):
        runtime = self.f.paths.runtime / str(self.f.uid)
        (runtime / "containers").rename(runtime / "run")
        before = self.f.snapshot()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertFalse(self.pending.exists())
        self.assertFalse(any(call[:2] == ("container", "exists") for call in self.calls))
        self.assert_retained()

    def test_drifted_public_policy_and_foreign_links_fail_without_mutation(self):
        self.unit.write_text("changed public policy\n")
        before = self.f.snapshot()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertEqual(self.calls, [])
        self.unit.write_text(
            inspection.public_policy(self.f.instance, self.f.platform, self.f.home, self.f.gid)[
                "unit"
            ].content
        )
        self.links[0].unlink()
        self.links[0].symlink_to("../foreign.service")
        before = self.f.snapshot()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertEqual(self.calls, [])

    def test_failed_stop_retains_intent_and_retry_finishes(self):
        self.native_failure = lambda args: args[1:3] == ["stop", self.unit.name]
        self.f.invoke("purge", expected=1)
        self.assertEqual(json.loads(self.pending.read_text())["phase"], "prepared")
        self.assertTrue(self.unit.exists())
        self.assert_retained()
        self.native_failure = None
        self.f.invoke("purge")
        self.assertFalse(self.pending.exists())
        self.assert_retained()

    def test_masked_stop_failure_and_inactive_orphan_never_retire_policy(self):
        self.masked_stop = True
        self.f.invoke("purge", expected=1)
        self.assertFalse(self.active)
        self.assertTrue(self.containers[self.name])
        self.assertTrue(self.unit.exists())
        self.assertEqual(json.loads(self.pending.read_text())["phase"], "prepared")
        self.f.invoke("purge", expected=1)
        self.assertTrue(self.unit.exists())
        self.assert_retained()

    def test_stale_cached_unit_is_reloaded_before_stop_and_dropins_block_stop(self):
        self.stale = True
        self.native_failure = lambda args: args[1:2] == ["daemon-reload"]
        self.f.invoke("purge", expected=1)
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))
        self.native_failure = None
        self.dropins = "/fixture/foreign.conf"
        self.f.invoke("purge", expected=1)
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))
        self.dropins = ""
        self.f.invoke("purge")
        reload_index = next(
            i for i, call in enumerate(self.calls) if call[1:2] == ("daemon-reload",)
        )
        stop_index = next(i for i, call in enumerate(self.calls) if call[1:2] == ("stop",))
        self.assertLess(reload_index, stop_index)

    def test_missing_storage_and_native_absence_errors_fail_closed(self):
        database = self.f.home / ".local/share/containers/storage/db.sql"
        original = database.read_bytes()
        database.unlink()
        self.f.invoke("purge", expected=1)
        self.manager.assert_not_called()
        self.assertFalse(any(call[:2] == ("container", "exists") for call in self.calls))
        self.assertTrue(self.unit.exists())
        self.f.owned(database, original, 0o600)
        self.exists_error = True
        self.active = False
        self.f.invoke("purge", expected=1)
        self.assertTrue(self.unit.exists())
        self.assertTrue(self.pending.exists())

    def test_failed_trust_refresh_resumes_after_unit_removal_and_preserves_other_markers(self):
        self.add_certificates()
        for name in (".reconcile.pending", ".trust.pending"):
            self.f.owned(self.f.private.parent / name, b"pending\n", 0o600)
        self.native_failure = lambda args: args == [self.f.platform["trust"], "extract-compat"]
        self.f.invoke("purge", expected=1)
        self.assertFalse(self.unit.exists())
        self.assertEqual(json.loads(self.pending.read_text())["phase"], "services_stopped")
        self.native_failure = None
        self.f.invoke("purge")
        for name in (".reconcile.pending", ".trust.pending"):
            self.assertEqual((self.f.private.parent / name).read_bytes(), b"pending\n")
        self.assert_retained()

    def test_changed_declaration_cannot_redirect_interrupted_retirement(self):
        policies = self.add_certificates()
        original_remove = retirement.remove_managed_file

        def interrupt(path):
            if path == policies["manager_ca"].path:
                raise operations.RunnerError("synthetic retirement interruption")
            return original_remove(path)

        with mock.patch.object(retirement, "remove_managed_file", side_effect=interrupt):
            self.f.invoke("purge", expected=1)
        self.assertFalse(self.unit.exists())
        self.assertTrue(policies["manager_ca"].path.exists())
        common = self.f.root / "common.toml"
        original = common.read_text()
        common.write_text(original.replace("gitlab.example", "other.example"))
        before = self.f.snapshot()
        self.calls.clear()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertEqual(self.calls, [])
        common.write_text(original)
        self.f.invoke("purge")
        self.assertFalse(policies["manager_ca"].path.exists())
        self.assert_retained()

    def test_preview_reports_intent_and_reconcile_refuses_it_before_native_preparation(self):
        self.native_failure = lambda args: args[1:2] == ["daemon-reload"]
        self.f.invoke("purge", expected=1)
        self.native_failure = None
        before = self.f.snapshot()
        self.calls.clear()
        output, _ = self.f.invoke("plan")
        self.assertTrue(any("retirement" in change["text"] for change in json.loads(output)))
        self.f.invoke("reconcile", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertEqual(self.calls, [])
        self.f.native.assert_not_called()

    def test_retirement_phase_rejects_restarted_services(self):
        self.native_failure = lambda args: args == [self.f.platform["trust"], "extract-compat"]
        self.add_certificates()
        self.f.invoke("purge", expected=1)
        self.socket_active = True
        before = self.f.snapshot()
        self.calls.clear()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))
        self.assertTrue(self.pending.exists())

    def test_post_reload_identity_change_blocks_every_stop(self):
        self.dropins_after_reload = "/fixture/foreign.conf"
        self.f.invoke("purge", expected=1)
        self.assertTrue(self.active)
        self.assertTrue(self.unit.exists())
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))
        self.assertEqual(json.loads(self.pending.read_text())["phase"], "prepared")
        self.assert_retained()

    def test_foreign_public_file_owner_fails_before_native_mutation(self):
        original = inspection.path_info

        def foreign(path):
            info = original(path)
            if path == self.unit and info is not None:
                fields = list(info)
                fields[4] = self.f.uid + 1
                return os.stat_result(fields)
            return info

        before = self.f.snapshot()
        with mock.patch.object(inspection, "path_info", side_effect=foreign):
            self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertEqual(self.calls, [])

    def test_invalid_retirement_phase_is_never_repaired_or_consumed(self):
        self.native_failure = lambda args: args[1:2] == ["daemon-reload"]
        self.f.invoke("purge", expected=1)
        marker = json.loads(self.pending.read_text())
        marker["phase"] = "unknown"
        self.pending.write_text(json.dumps(marker))
        before = self.f.snapshot()
        self.calls.clear()
        self.f.invoke("purge", expected=1)
        self.f.invoke("preflight", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertEqual(self.calls, [])

    def test_missing_user_bus_never_prepares_runtime(self):
        self.bus.close()
        (self.f.paths.runtime / str(self.f.uid) / "bus").unlink()
        before = self.f.snapshot()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertEqual(self.calls, [])

    def test_cold_runtime_is_rejected_before_any_podman_query(self):
        (self.f.paths.runtime / str(self.f.uid) / "libpod/tmp/alive").unlink()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.initializations, [])
        self.assertFalse(any(call[:2] == ("container", "exists") for call in self.calls))
        self.manager.assert_not_called()
        self.assertTrue(self.unit.exists())
        self.assert_retained()

    def test_retry_reloads_before_deleting_remaining_policy(self):
        policies = self.add_certificates()
        original_remove = retirement.remove_managed_file

        def interrupt(path):
            if path == policies["manager_ca"].path:
                raise operations.RunnerError("synthetic interruption")
            return original_remove(path)

        with mock.patch.object(retirement, "remove_managed_file", side_effect=interrupt):
            self.f.invoke("purge", expected=1)
        self.stale = True
        self.dropins_after_reload = "/fixture/foreign.conf"
        before = self.f.snapshot()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertTrue(policies["manager_ca"].path.exists())
        self.assert_retained()

    def test_repeat_refuses_stale_units_and_missing_socket_prerequisite(self):
        self.f.invoke("purge")
        self.stale = True
        before = self.f.snapshot()
        self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.stale = False
        original = self.properties

        def missing_socket(unit):
            values = original(unit)
            if unit == "podman.socket":
                values |= {"LoadState": "not-found", "FragmentPath": "", "UnitFileState": ""}
            return values

        with mock.patch.object(self, "properties", side_effect=missing_socket):
            self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assert_retained()

    def test_restored_anchor_records_trust_refresh_before_its_removal(self):
        policies = self.add_certificates()
        anchor = policies["system_ca"]
        anchor.path.unlink()
        self.native_failure = lambda args: args[1:3] == ["stop", self.unit.name]
        self.f.invoke("purge", expected=1)
        self.assertFalse(json.loads(self.pending.read_text())["trust"])
        self.f.owned(anchor.path, anchor.content.encode(), anchor.mode)
        original_remove = retirement.remove_managed_file

        def assert_intent(path):
            if path == anchor.path:
                self.assertTrue(json.loads(self.pending.read_text())["trust"])
            return original_remove(path)

        self.native_failure = None
        self.calls.clear()
        with mock.patch.object(retirement, "remove_managed_file", side_effect=assert_intent):
            self.f.invoke("purge")
        self.assertIn((self.f.platform["trust"], "extract-compat"), self.calls)
        self.assertFalse(anchor.path.exists())
        self.assert_retained()

    def test_active_identity_inspection_uses_the_same_live_confined_engine(self):
        self.manager_patch.stop()
        self.f.invoke("purge")
        self.assertEqual(self.initializations, [])
        self.assert_retained()

    def test_enablement_directory_and_link_group_conflicts_fail_before_mutation(self):
        original = inspection.path_info
        for target in (self.links[0].parent, self.links[1].parent, self.links[0]):

            def foreign_group(path, target=target):
                info = original(path)
                if path == target and info is not None:
                    fields = list(info)
                    fields[5] = self.f.gid + 1
                    return os.stat_result(fields)
                return info

            before = self.f.snapshot()
            with mock.patch.object(inspection, "path_info", side_effect=foreign_group):
                self.f.invoke("purge", expected=1)
            self.assertEqual(self.f.snapshot(), before)
            self.assertEqual(self.calls, [])

    def test_loaded_unit_without_its_expected_name_is_rejected(self):
        original = self.properties

        def unnamed(unit):
            values = original(unit)
            values["Names"] = ""
            return values

        before = self.f.snapshot()
        with mock.patch.object(self, "properties", side_effect=unnamed):
            self.f.invoke("purge", expected=1)
        self.assertEqual(self.f.snapshot(), before)
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))

    def test_enablement_parent_drift_during_reload_blocks_retirement(self):
        original = inspection.path_info
        drift = False
        native = self.native

        def reload_changes_group(entry, argv, **kwargs):
            nonlocal drift
            result = native(entry, argv, **kwargs)
            if argv[1:] == ["--user", "daemon-reload"]:
                drift = True
            return result

        def changed(path):
            info = original(path)
            if drift and path == self.links[0].parent and info is not None:
                fields = list(info)
                fields[5] = self.f.gid + 1
                return os.stat_result(fields)
            return info

        with (
            mock.patch.object(operations, "run_as", side_effect=reload_changes_group),
            mock.patch.object(inspection, "path_info", side_effect=changed),
        ):
            self.f.invoke("purge", expected=1)
        self.assertTrue(self.links[0].is_symlink())
        self.assertTrue(self.unit.exists())
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))
        self.assert_retained()

    def test_empty_or_uninitialized_database_never_reaches_podman(self):
        path = self.f.home / ".local/share/containers/storage/db.sql"
        for initialize in (False, True):
            path.write_bytes(b"")
            if initialize:
                with closing(sqlite3.connect(path)) as database:
                    database.execute("CREATE TABLE unrelated (value INTEGER)")
                    database.commit()
            self.preserved = self.retained()
            self.calls.clear()
            self.f.invoke("purge", expected=1)
            self.assertFalse(any(call[:2] == ("container", "exists") for call in self.calls))
            self.manager.assert_not_called()
            self.assertTrue(self.unit.exists())
            self.assertEqual(self.initializations, [])
            self.assert_retained()

    def test_active_process_using_another_database_is_never_stopped(self):
        other = self.f.root / "other-engine.sqlite"
        other.write_text("fixture unrelated engine")
        descriptor = self.f.paths.proc_root / "4242/fd/5"
        descriptor.unlink()
        descriptor.symlink_to(other)
        self.f.invoke("purge", expected=1)
        self.assertTrue(self.active)
        self.assertTrue(self.unit.exists())
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))
        self.manager.assert_not_called()
        self.assert_retained()

    def test_unit_changed_before_reload_is_never_used_to_stop_the_manager(self):
        native = self.native

        def replace_source(entry, argv, **kwargs):
            if argv[1:] == ["--user", "daemon-reload"]:
                self.unit.write_text("fixture changed stop policy\n")
            return native(entry, argv, **kwargs)

        with mock.patch.object(operations, "run_as", side_effect=replace_source):
            self.f.invoke("purge", expected=1)
        self.assertTrue(self.active)
        self.assertTrue(self.containers[self.name])
        self.assertFalse(any(call[1:2] == ("stop",) for call in self.calls))
        self.assertEqual(json.loads(self.pending.read_text())["phase"], "prepared")
        self.assert_retained()

    def test_live_wal_metadata_is_read_without_changing_retained_payloads(self):
        path = self.f.home / ".local/share/containers/storage/db.sql"
        with closing(sqlite3.connect(path)) as database:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute("CREATE TABLE fixture_wal (value INTEGER)")
            database.execute("INSERT INTO fixture_wal VALUES (42)")
            database.commit()
            before = self.retained()
            self.f.invoke("purge")
            after = self.retained()
            self.assertEqual(set(before), set(after))
            for name, value in before.items():
                if name.endswith("db.sql-shm"):
                    # SQLite readers update shared reader coordination, not durable payloads.
                    self.assertEqual(after[name][:4], value[:4])
                else:
                    self.assertEqual(after[name], value)
            self.assertIs(self.containers["previous-stopped"], False)
            self.assertIs(self.containers["unrelated"], True)

    def test_policy_reappearing_after_refresh_retains_recovery_intent(self):
        policies = self.add_certificates()
        trust = self.trust

        def restore_policy(argv, **kwargs):
            result = trust(argv, **kwargs)
            policy = policies["template"]
            self.f.owned(policy.path, policy.content.encode(), policy.mode)
            return result

        with mock.patch.object(operations, "run", side_effect=restore_policy):
            self.f.invoke("purge", expected=1)
        self.assertTrue(policies["template"].path.exists())
        self.assertEqual(json.loads(self.pending.read_text())["phase"], "services_stopped")
        self.f.invoke("purge")
        self.assertFalse(policies["template"].path.exists())
        self.assert_retained()

    def test_anchor_restored_between_unlinks_records_trust_before_removal(self):
        policies = self.add_certificates()
        anchor = policies["system_ca"]
        anchor.path.unlink()
        remove = retirement.remove_managed_file

        def restore_anchor(path):
            result = remove(path)
            if path == self.unit:
                self.f.owned(anchor.path, anchor.content.encode(), anchor.mode)
            return result

        with mock.patch.object(retirement, "remove_managed_file", side_effect=restore_anchor):
            self.f.invoke("purge")
        self.assertIn((self.f.platform["trust"], "extract-compat"), self.calls)
        self.assertFalse(anchor.path.exists())
        self.assert_retained()
