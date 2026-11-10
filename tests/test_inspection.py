# pyright: standard
"""Exercise static previews through the CLI with isolated policy and metadata."""

from __future__ import annotations

import builtins
import grp
import io
import json
import os
import pwd
import re
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from runnerctl import cli, inspection, operations
from runnerctl.config import PLATFORMS, HostPaths, load_instances
from runnerctl.model import render_registration_template, render_service

FIXTURES = Path(__file__).parent / "fixtures"


class InspectionCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.uid = os.getuid() or 1001
        self.gid = os.getgid() if os.getuid() else 1001
        self.input = self.root / "frontend.toml"
        content = (FIXTURES / "frontend.toml").read_text()
        self.input.write_text(re.sub(r"(?m)^uid = \d+$", f"uid = {self.uid}", content))
        (self.root / "common.toml").write_bytes((FIXTURES / "common.toml").read_bytes())
        self.instance = load_instances([self.input])["frontend"]
        account = self.instance["account"]
        self.user = account["user"]
        self.entry = pwd.struct_passwd(
            (self.user, "x", self.uid, self.gid, "", account["home"], "/bin/bash")
        )
        self.paths = HostPaths(
            self.root / "subuid",
            self.root / "subgid",
            self.root / "run",
            self.root / "homes",
            self.root / "proc",
        )
        self.home = self.paths.home_root / self.user
        self.platform = PLATFORMS["arch"] | {
            "caAnchorDirectory": str(self.root / "anchors"),
            "containerCertsDirectory": str(self.root / "certs"),
        }
        self.lock_path = self.root / "runner.lock"
        self.real_lock = operations.operation_lock
        self.real_info = inspection.path_info
        self.command = ""
        self.present = False
        self.private = self.home / "gitlab-runner/config/config.toml"
        self.private_marker = b"fixture-only-private-registration"
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(operations, "DEFAULT_PATHS", self.paths))
        stack.enter_context(
            mock.patch.object(inspection, "path_info", side_effect=self.system_info)
        )
        stack.enter_context(mock.patch.object(cli, "platform_paths", return_value=self.platform))
        stack.enter_context(mock.patch.object(operations.os, "geteuid", return_value=0))
        self.account_lookup = stack.enter_context(
            mock.patch.object(inspection.pwd, "getpwnam", side_effect=self.account)
        )
        stack.enter_context(
            mock.patch.object(
                inspection.pwd, "getpwuid", side_effect=KeyError("unused fixture UID")
            )
        )
        stack.enter_context(
            mock.patch.object(
                inspection.grp, "getgrnam", side_effect=KeyError("missing fixture group")
            )
        )
        stack.enter_context(
            mock.patch.object(
                inspection.grp,
                "getgrgid",
                return_value=grp.struct_group((self.user, "x", self.gid, [])),
            )
        )
        stack.enter_context(
            mock.patch.object(inspection.os, "getgrouplist", return_value=[self.gid])
        )
        self.native = stack.enter_context(
            mock.patch.object(
                operations,
                "run",
                side_effect=AssertionError("native command during static inspection"),
            )
        )
        stack.enter_context(mock.patch.object(operations, "operation_lock", side_effect=self.lock))
        for name in ("run_as", "registration_metadata", "ensure_account"):
            stack.enter_context(
                mock.patch.object(
                    operations, name, side_effect=AssertionError(f"unexpected {name}")
                )
            )

    def system_info(self, path):
        info = self.real_info(path)
        if info is not None and path in (self.paths.subuid, self.paths.subgid):
            # Unprivileged tests simulate root-owned system allocation files.
            fields = list(info)
            fields[4] = 0
            return os.stat_result(fields)
        return info

    def lock(self):
        self.assertIn(self.command, {"reconcile", "purge"})
        return self.real_lock(self.lock_path)

    def account(self, user):
        self.assertEqual(user, self.user)
        if not self.present:
            raise KeyError(user)
        return self.entry

    def owned(self, path, body=None, mode=0o700):
        path.parent.mkdir(parents=True, exist_ok=True)
        if body is None:
            path.mkdir(exist_ok=True)
        else:
            path.write_bytes(body)
        path.chmod(mode)
        if os.getuid() == 0:
            os.chown(path, self.uid, self.gid)

    def ready(self):
        self.present = True
        directories = [
            self.home,
            self.home / "gitlab-runner",
            self.private.parent,
            self.home / "gitlab-runner/cache",
            self.home / ".config",
            self.home / ".config/systemd",
            self.home / ".config/systemd/user",
        ]
        for path in directories:
            self.owned(path)
        for path, key in ((self.paths.subuid, "subUid"), (self.paths.subgid, "subGid")):
            value = self.instance["account"][key]
            path.write_text(f"{self.user}:{value['start']}:{value['count']}\n")
        self.owned(
            self.private.parent / "registration-template.toml",
            render_registration_template(self.instance).encode(),
            0o600,
        )
        self.unit = (
            self.home / ".config/systemd/user" / f"{self.instance['runner']['serviceName']}.service"
        )
        self.owned(self.unit, render_service(self.instance, self.platform).encode(), 0o600)
        self.owned(self.private, b"\xff" + self.private_marker, 0o600)
        self.owned(self.home / ".local/share/containers/storage", mode=0o700)
        self.owned(
            self.home / ".local/share/containers/storage/db.sql", b"fixture engine state", 0o600
        )

    def snapshot(self):
        result = {}
        for path in self.root.rglob("*"):
            info = path.lstat()
            body = (
                os.readlink(path)
                if stat.S_ISLNK(info.st_mode)
                else path.read_bytes()
                if stat.S_ISREG(info.st_mode)
                else None
            )
            result[str(path.relative_to(self.root))] = (
                info.st_mode,
                info.st_uid,
                info.st_gid,
                info.st_ino,
                info.st_mtime_ns,
                body,
            )
        return result

    def guarded_open(self, original):
        def open_public(path, *args, **kwargs):
            if isinstance(path, int):
                target = Path(os.readlink(f"/proc/self/fd/{path}"))
            else:
                target = Path(os.fsdecode(path))
                if not target.is_absolute():
                    parent = kwargs.get("dir_fd")
                    target = (
                        Path(os.readlink(f"/proc/self/fd/{parent}"))
                        if parent is not None
                        else Path.cwd()
                    ) / target
            if target == self.private:
                raise AssertionError("registration contents must never be opened during preview")
            return original(path, *args, **kwargs)

        return open_public

    def invoke(self, command, *, expected=0, additional=(), json_output=True, tty=False):
        self.command = command
        args = ["runnerctl", "--platform", "arch", "-c", str(self.input)]
        for path in additional:
            args.extend(["-c", str(path)])
        args.extend([command] if command == "validate" else [command, "frontend"])
        if command == "plan" and json_output:
            args.append("--json")
        stdout, stderr = StringIO(), StringIO()
        with (
            mock.patch.object(sys, "argv", args),
            mock.patch.object(builtins, "open", self.guarded_open(builtins.open)),
            mock.patch.object(io, "open", self.guarded_open(io.open)),
            mock.patch.object(os, "open", self.guarded_open(os.open)),
            mock.patch.object(stdout, "isatty", return_value=tty),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as exited,
        ):
            cli.main_cli()
        self.assertEqual(exited.exception.code, expected, stderr.getvalue())
        self.assertNotIn(self.private_marker.decode(), stdout.getvalue() + stderr.getvalue())
        return stdout.getvalue(), stderr.getvalue()

    def test_terminal_colors_preserve_plain_text_and_json_protocols(self):
        with mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=True):
            for command in ("validate", "plan"):
                with self.subTest(command=command):
                    plain, _ = self.invoke(command, json_output=False)
                    colored, _ = self.invoke(command, json_output=False, tty=True)
                    self.assertIn("\033[", colored)
                    self.assertEqual(re.sub(r"\033\[[0-9;]*m", "", colored), plain)
                    self.assertNotIn("\033", plain)
                    for disabled in ({"NO_COLOR": ""}, {"TERM": "dumb"}, {"CI": "1"}):
                        with mock.patch.dict(os.environ, disabled):
                            output, _ = self.invoke(command, json_output=False, tty=True)
                            self.assertEqual(output, plain)
            output, _ = self.invoke("plan", tty=True)
            self.assertTrue(json.loads(output))
            self.assertNotIn("\033", output)

    def test_clean_first_install_needs_no_packages_runtime_or_lock(self):
        before = self.snapshot()
        self.invoke("preflight")
        output, _ = self.invoke("plan")
        changes = json.loads(output)
        self.assertTrue(changes)
        self.assertTrue(all(set(change) == {"kind", "text"} for change in changes))
        self.assertTrue(any(change["kind"] == "+" for change in changes))
        self.assertTrue(
            any(change["kind"] == "-" and "deferred" in change["text"] for change in changes)
        )
        self.assertEqual(self.snapshot(), before)
        self.native.assert_not_called()

    def test_repeat_inspection_preserves_runtime_and_never_reads_registration(self):
        self.ready()
        before = self.snapshot()
        first, _ = self.invoke("plan")
        second, _ = self.invoke("plan")
        changes = json.loads(first)
        self.assertEqual(first, second)
        self.assertFalse(any(change["kind"] in {"+", "~", "!"} for change in changes))
        self.assertTrue(
            any(
                str(self.private) in change["text"] and "unobserved" in change["text"]
                for change in changes
            )
        )
        self.assertEqual(self.snapshot(), before)

    def test_duplicate_numeric_allocation_blocks_both_preview_commands(self):
        self.ready()
        for path in (self.paths.subuid, self.paths.subgid):
            original = path.read_bytes()
            path.write_bytes(original + f"{self.uid}:300000:65536\n".encode())
            before = self.snapshot()
            for command in ("preflight", "plan"):
                self.invoke(command, expected=1)
            self.assertEqual(self.snapshot(), before)
            path.write_bytes(original)

    def test_invalid_marker_is_not_repaired_or_erased(self):
        self.ready()
        marker = self.private.parent / ".reconcile.pending"
        self.owned(marker, b"invalid fixture marker", 0o600)
        before = self.snapshot()
        self.invoke("preflight", expected=1)
        self.invoke("plan", expected=1)
        self.assertEqual(self.snapshot(), before)

    def test_foreign_ownership_is_rejected_even_when_running_as_root(self):
        self.ready()
        original = inspection.path_info

        def foreign_owner(path):
            info = original(path)
            if path == self.unit and info is not None:
                fields = list(info)
                fields[4] = self.uid + 1
                return os.stat_result(fields)
            return info

        before = self.snapshot()
        with mock.patch.object(inspection, "path_info", side_effect=foreign_owner):
            self.invoke("preflight", expected=1)
            self.invoke("plan", expected=1)
        self.assertEqual(self.snapshot(), before)
        self.native.assert_not_called()

    def test_foreign_system_allocations_fail_before_native_preparation(self):
        self.ready()
        original = inspection.path_info
        for target in (self.paths.subuid, self.paths.subgid):

            def foreign_owner(path, target=target):
                info = original(path)
                if path == target and info is not None:
                    fields = list(info)
                    fields[4] = self.uid
                    return os.stat_result(fields)
                return info

            self.lock_path.touch(mode=0o600)
            before = self.snapshot()
            with mock.patch.object(inspection, "path_info", side_effect=foreign_owner):
                for command in ("preflight", "plan", "reconcile"):
                    self.invoke(command, expected=1)
            self.assertEqual(self.snapshot(), before)
            self.native.assert_not_called()

    def test_owned_policy_drift_is_planned_without_overwriting_it(self):
        self.ready()
        self.unit.write_text("fixture changed public unit\n")
        before = self.snapshot()
        output, _ = self.invoke("plan")
        self.assertTrue(
            any(
                change["kind"] == "~" and str(self.unit) in change["text"]
                for change in json.loads(output)
            )
        )
        self.assertEqual(self.snapshot(), before)

    def test_valid_pending_work_is_reported_without_resuming_it(self):
        self.ready()
        marker = self.private.parent / ".trust.pending"
        self.owned(marker, b"pending\n", 0o600)
        before = self.snapshot()
        output, _ = self.invoke("plan")
        self.assertTrue(
            any(
                change["kind"] == "~" and str(marker) in change["text"]
                for change in json.loads(output)
            )
        )
        self.assertEqual(self.snapshot(), before)
        self.native.assert_not_called()

    def test_whole_set_collision_fails_before_account_observation(self):
        second = self.root / "dotnet.toml"
        content = (FIXTURES / "dotnet.toml").read_text()
        second.write_text(re.sub(r"(?m)^uid = \d+$", f"uid = {self.uid}", content))
        self.invoke("plan", expected=1, additional=[second])
        self.account_lookup.assert_not_called()

    def test_real_static_recheck_stops_reconcile_before_any_native_call(self):
        self.ready()
        self.invoke("preflight")
        sentinel = self.root / "sentinel"
        sentinel.write_text("unchanged")
        self.unit.unlink()
        self.unit.symlink_to(sentinel)
        self.lock_path.touch(mode=0o600)
        before = self.snapshot()
        _, error = self.invoke("reconcile", expected=1)
        self.assertIn("unsafe", error)
        self.assertEqual(self.snapshot(), before)
        self.native.assert_not_called()
