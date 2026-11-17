# pyright: standard
"""Exercise complete removal with a synthetic host: accounts, processes and native boundaries."""

from __future__ import annotations

import dataclasses
import grp
import os
import pwd
import shutil
import signal
import subprocess
import sys
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import test_inspection as support
from nix_adapter import remove_subordinate_range

from runnerctl import cli, diagnostics, inspection, operations, removal
from runnerctl.config import load_instances

TOKEN = "glrt-synthetic_Removal-Token"
REAL_RUN = operations.run
FOREIGN_UID = 54321


class Host:
    """A fully provisioned synthetic instance behind every removal seam."""

    def __init__(self, case: unittest.TestCase, *, certificates: bool = False):
        self.case = case
        self.f = support.InspectionCliTests()
        self.f.setUp()
        self.stack = ExitStack()
        self.stack.callback(self.f.doCleanups)
        f = self.f
        f.ready()
        f.lock_path.touch(mode=0o600)
        self.uid, self.gid, self.user, self.home = f.uid, f.gid, f.user, f.home
        self.paths = dataclasses.replace(f.paths, linger=f.root / "linger")
        self.config = f.private
        self.linger = self.paths.linger / self.user
        f.owned(self.paths.linger, mode=0o755)
        f.owned(self.linger, b"", 0o644)
        self.root_owned = {self.linger}
        self.foreign: set[Path] = set()
        self.copies: list[Path] = []
        if certificates:
            self.certificates()
        self.platform = dict(f.platform)
        for name in ("loginctl", "systemctl", "curl", "trust", "userdel", "groupdel", "rm"):
            self.platform[name] = str(f.root / "bin" / name)
            f.owned(f.root / "bin" / name, b"", 0o755)
        self.proc = self.paths.proc_root
        self.process(1, (0, 0, 0, 0))
        (self.proc / "1/mountinfo").write_text("21 1 0:20 / / rw - ext4 /dev/root rw\n")
        (self.proc / "self").symlink_to("1")
        self.accounts = {self.user: f.entry}
        self.groups = {self.user: grp.struct_group((self.user, "x", self.gid, []))}
        self.registration = "present"
        self.metadata = {"token": TOKEN, "id": "42"}
        self.curl = subprocess.CompletedProcess([], 0, "204", "")
        self.usergroups = True
        self.failing: set[str] = set()
        self.fatal: dict[int, set[int]] = {}
        self.calls: list[tuple[str, list[str], dict]] = []
        self.signals: list[tuple[int, int]] = []
        self.sleeps = 0
        self.locked = 0
        # Host changes that happen at a point in time: on the next poll, or after a tool runs.
        self.on_sleep: list = []
        self.after: dict = {}
        self.inert: set[str] = set()
        self.patch()

    def patch(self):
        enter = self.stack.enter_context
        info = inspection.path_info

        def path_info(path):
            result = info(path)
            if result is not None and (path in self.root_owned or path in self.foreign):
                fields = list(result)
                fields[4:6] = [FOREIGN_UID, FOREIGN_UID] if path in self.foreign else [0, 0]
                return os.stat_result(fields)
            return result

        def subordinate(path, user, desired, *, aliases=()):
            return remove_subordinate_range(
                path, user, desired, uid=os.getuid(), gid=os.getgid(), aliases=aliases
            )

        def by_uid(uid):
            return next(entry for entry in self.accounts.values() if entry.pw_uid == uid)

        def by_gid(gid):
            return next(group for group in self.groups.values() if group.gr_gid == gid)

        def missing(lookup):
            def wrapped(key):
                try:
                    return lookup(key)
                except (KeyError, StopIteration):
                    raise KeyError(key) from None

            return wrapped

        enter(mock.patch.object(operations, "DEFAULT_PATHS", self.paths))
        enter(mock.patch.object(inspection, "path_info", side_effect=path_info))
        enter(mock.patch.object(cli, "platform_paths", side_effect=lambda _: self.platform))
        enter(mock.patch.object(pwd, "getpwnam", side_effect=missing(self.accounts.__getitem__)))
        enter(mock.patch.object(pwd, "getpwuid", side_effect=missing(by_uid)))
        enter(mock.patch.object(pwd, "getpwall", side_effect=lambda: list(self.accounts.values())))
        enter(mock.patch.object(grp, "getgrnam", side_effect=missing(self.groups.__getitem__)))
        enter(mock.patch.object(grp, "getgrgid", side_effect=missing(by_gid)))
        enter(mock.patch.object(operations, "run", side_effect=self.run))
        enter(mock.patch.object(operations, "operation_lock", side_effect=self.lock))
        enter(mock.patch.object(operations, "registration_metadata", side_effect=self.registered))
        enter(mock.patch.object(removal, "remove_subordinate_range", side_effect=subordinate))
        enter(mock.patch.object(removal, "sleep", side_effect=self.sleep))
        enter(mock.patch.object(removal, "signal_process", side_effect=self.signal))

    def close(self):
        self.stack.close()

    def certificates(self):
        f = self.f
        self.source = f.root / "public.crt"
        self.source.write_text("fixture public certificate\n")
        f.input.write_text(f.input.read_text() + '\n[gitlab]\nca_certificate = "public.crt"\n')
        f.instance = load_instances([f.input])["frontend"]
        policies = inspection.public_policy(f.instance, f.platform, f.home, f.gid)
        for name in ("system_ca", "registry_ca"):
            path = policies[name].path
            f.owned(path.parent, mode=0o755)
            f.owned(path, b"rotated certificate content\n", 0o644)
            self.copies.append(path)
            self.root_owned.add(path)

    def process(self, pid, uids, *, state="S", tasks=None, ppid=1, task_state=None):
        def status(path, values, current):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                f"Name:\tfixture\nState:\t{current} (fixture)\nPPid:\t{ppid}\n"
                f"Uid:\t{values[0]}\t{values[1]}\t{values[2]}\t{values[3]}\n"
            )

        status(self.proc / str(pid) / "status", uids, state)
        for task, values in (tasks or {pid: uids}).items():
            status(
                self.proc / str(pid) / "task" / str(task) / "status", values, task_state or state
            )

    def lock(self):
        self.locked += 1
        return self.f.real_lock(self.f.lock_path)

    def registered(self, path):
        self.case.assertEqual(path, self.config)
        self.case.assertTrue(path.is_file())
        if self.registration == "invalid":
            raise operations.RunnerError("dedicated Runner config is invalid TOML")
        return dict(self.metadata) if self.registration == "present" else {}

    def sleep(self, seconds):
        self.case.assertEqual(seconds, 1)
        self.sleeps += 1
        while self.on_sleep:
            self.on_sleep.pop(0)()

    def signal(self, pid, sig, matches):
        self.case.assertTrue(matches(pid))
        self.signals.append((pid, sig))
        if sig in self.fatal.get(pid, {signal.SIGTERM, signal.SIGKILL}):
            shutil.rmtree(self.proc / str(pid))

    def intercept(self, tool, argv):
        """Apply a failure, a timed host change or an inert result for `tool`."""
        if tool in self.failing:
            raise operations.RunnerError(f"command failed with exit code 1: {tool}")
        if tool in self.after:
            self.after.pop(tool)()
        if tool in self.inert:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return None

    def run(self, argv, **kwargs):
        tool = Path(argv[0]).name
        self.case.assertEqual(argv[0], self.platform[tool])
        self.calls.append((tool, argv[1:], kwargs))
        intercepted = self.intercept(tool, argv)
        if intercepted is not None:
            return intercepted
        if tool == "loginctl" and argv[1] == "disable-linger":
            self.linger.unlink(missing_ok=True)
        elif tool == "loginctl":
            return subprocess.CompletedProcess(argv, 1, "", "")
        elif tool == "curl":
            return subprocess.CompletedProcess(argv, self.curl.returncode, self.curl.stdout, "")
        elif tool == "userdel":
            del self.accounts[argv[-1]]
            if self.usergroups:
                self.groups.pop(argv[-1], None)
            if "--remove" in argv:
                shutil.rmtree(self.home)
        elif tool == "groupdel":
            del self.groups[argv[-1]]
        elif tool == "rm":
            self.case.assertEqual(
                argv[1:], ["--recursive", "--one-file-system", "--", str(self.home)]
            )
            shutil.rmtree(self.home)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def invoke(self, *flags, expected=0):
        args = ["runnerctl", "--platform", "arch", "-c", str(self.f.input), "remove", "frontend"]
        stdout, stderr = StringIO(), StringIO()
        redacted = diagnostics.redacted
        with (
            mock.patch.object(sys, "argv", [*args, *flags]),
            # The CLI redacts error text, so the raw text is checked before that.
            mock.patch.object(diagnostics, "redacted", side_effect=redacted) as raw,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.case.assertRaises(SystemExit) as exited,
        ):
            cli.main_cli()
        self.case.assertEqual(exited.exception.code, expected, stderr.getvalue())
        self.case.assertNotIn(TOKEN, stdout.getvalue() + stderr.getvalue())
        self.case.assertNotIn(TOKEN, "".join(str(call.args[0]) for call in raw.call_args_list))
        return stdout.getvalue(), stderr.getvalue()

    def tools(self):
        return [tool for tool, _, _ in self.calls]

    def allocations(self):
        return self.paths.subuid.read_text() + self.paths.subgid.read_text()

    def assert_absent(self):
        self.case.assertEqual((self.accounts, self.groups), ({}, {}))
        self.case.assertFalse(self.home.exists())
        self.case.assertFalse(self.linger.exists())
        self.case.assertEqual(self.allocations(), "")
        self.case.assertFalse(any(path.exists() for path in self.copies))


def _another(host, **changes):
    fields = {"name": "other", "uid": 4000, "gid": 4000, "dir": "/home/other"}
    fields |= changes
    host.accounts[fields["name"]] = pwd.struct_passwd(
        (fields["name"], "x", fields["uid"], fields["gid"], "", fields["dir"], "/bin/sh")
    )


def _foreign_name(host):
    _another(host, name=host.user)


def _foreign_uid(host):
    del host.accounts[host.user]
    _another(host, uid=host.uid)


def _other_home(host):
    _another(host, name=host.user, uid=host.uid, gid=host.gid)


def _members(host):
    host.groups[host.user] = grp.struct_group((host.user, "x", host.gid, ["other"]))


def _shared_group(host):
    _another(host, gid=host.gid)


def _other_group(host):
    host.groups[host.user] = grp.struct_group((host.user, "x", host.gid + 1, []))


def _leftover_group(host):
    del host.accounts[host.user]
    host.groups[host.user] = grp.struct_group((host.user, "x", host.uid + 1, []))


def _home_link(host):
    shutil.rmtree(host.home)
    host.home.symlink_to(host.f.root)


def _mount(host):
    (host.proc / "1/mountinfo").write_text(
        f"21 1 0:20 / / rw - ext4 /dev/root rw\n"
        f"99 21 0:55 / {host.home}/.local/share/a\\040b rw - overlay overlay rw\n"
    )


def _drifted(host):
    host.paths.subuid.write_text(f"{host.user}:165536:1000\n")


def _overlapping(host):
    host.paths.subgid.write_text(f"{host.user}:165536:65536\nother:165540:10\n")


def _missing(name):
    return lambda host: Path(host.platform[name]).unlink()


REFUSALS = {
    "different UID": _foreign_name,
    f"UID {os.getuid() or 1001} is owned by other": _foreign_uid,
    "different home": _other_home,
    "has members": _members,
    "primary group of another account": _shared_group,
    "not the Runner account's own group": _other_group,
    "run groupdel by hand": _leftover_group,
    "foreign owner": lambda host: host.foreign.add(host.home),
    "unsafe type": _home_link,
    "mount under the Runner home": _mount,
    "drifted Runner subordinate allocation": _drifted,
    "subgid": _overlapping,
    str(Path("subuid")): lambda host: host.foreign.add(host.paths.subuid),
    "linger": lambda host: host.root_owned.discard(host.linger),
    "anchors": lambda host: host.root_owned.discard(host.copies[0]),
    "registration is invalid": lambda host: setattr(host, "registration", "invalid"),
} | {
    f"executable is missing: {name}": _missing(name)
    for name in ("loginctl", "systemctl", "curl", "trust", "userdel", "groupdel", "rm")
}


class RemovalTests(unittest.TestCase):
    def host(self, **kwargs) -> Host:
        host = Host(self, **kwargs)
        self.addCleanup(host.close)
        return host

    def test_preview_lists_every_item_and_changes_nothing(self):
        host = self.host(certificates=True)
        host.process(700, (host.uid,) * 4)
        before = host.f.snapshot()
        output, error = host.invoke(expected=1)
        self.assertEqual(
            output.splitlines(),
            [
                f"- stop the user manager and kill every process of UID {host.uid}"
                " and its sub-UID range 165536:65536, including running containers",
                "- delete GitLab runner 42",
                f"- delete config {host.config}",
                f"- remove CA copy {host.copies[0]}",
                f"- remove CA copy {host.copies[1]}",
                "- refresh host trust",
                f"- remove sub-ID allocation {host.paths.subuid} 165536:65536",
                f"- remove sub-ID allocation {host.paths.subgid} 165536:65536",
                f"- remove linger {host.linger}",
                f"- delete account {host.user}",
                f"- delete group {host.user}",
                f"- delete home {host.home}",
            ],
        )
        self.assertEqual(error, "rerun with --yes to remove frontend\n")
        self.assertEqual(host.f.snapshot(), before)
        self.assertEqual((host.calls, host.signals, host.sleeps), ([], [], 0))
        self.assertEqual(host.locked, 1)
        self.assertIn(host.user, host.accounts)

    def test_preview_names_kept_runners_unknown_ids_and_observed_scope(self):
        host = self.host()
        host.paths.subuid.write_text("")
        del host.metadata["id"]
        output, _ = host.invoke(expected=1)
        self.assertIn(
            f"- stop the user manager and kill every process of UID {host.uid},"
            " including running containers\n",
            output,
        )
        self.assertIn("- delete GitLab runner (ID unknown)\n", output)
        self.assertNotIn(str(host.paths.subuid), output)
        self.assertNotIn("refresh host trust", output)
        host.registration = "invalid"
        output, _ = host.invoke("--keep-gitlab", expected=1)
        self.assertIn("- keep the GitLab runner (--keep-gitlab)\n", output)
        self.assertNotIn("delete config", output)
        self.assertEqual(host.calls, [])

    def test_removes_everything_in_order_and_repeats_unchanged(self):
        host = self.host(certificates=True)
        host.usergroups = False
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        url = "https://gitlab.example/api/v4/runners"
        self.assertEqual(
            [(tool, args) for tool, args, _ in host.calls],
            [
                ("loginctl", ["disable-linger", host.user]),
                ("systemctl", ["stop", f"user@{host.uid}.service"]),
                ("loginctl", ["terminate-user", host.user]),
                (
                    "curl",
                    "--disable --silent --show-error --request DELETE --data-urlencode token@-"
                    " --output /dev/null --write-out %{http_code} --connect-timeout 10"
                    f" --max-time 30 --cacert {host.source} {url}".split(),
                ),
                ("trust", ["extract-compat"]),
                ("userdel", ["--remove", host.user]),
                ("groupdel", [host.user]),
            ],
        )
        curl = host.calls[3][2]
        self.assertEqual(curl["input"], TOKEN)
        self.assertFalse(curl.get("public", False))
        self.assertFalse(host.calls[2][2]["check"])
        self.assertNotIn(TOKEN, repr([(args, {**kw, "input": None}) for _, args, kw in host.calls]))
        host.assert_absent()
        host.calls.clear()
        # A repeat needs no executable, even with a declared CA.
        Path(host.platform["trust"]).unlink()
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: unchanged\n")
        self.assertEqual(host.calls, [])

    def test_removes_partly_provisioned_instances(self):
        host = self.host()
        for path in (host.home / "gitlab-runner", host.home / ".config", host.home / ".local"):
            shutil.rmtree(path)
        host.linger.unlink()
        host.paths.subuid.write_text("")
        host.paths.subgid.unlink()
        host.process(710, (165540,) * 4)
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        self.assertEqual(
            host.tools(), ["loginctl", "systemctl", "loginctl", "userdel"], "no curl, trust or rm"
        )
        # Without an observed allocation, the sub-UID range belongs to nobody.
        self.assertEqual(host.signals, [])
        host.close()

        host = self.host()
        shutil.rmtree(host.home)
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        self.assertEqual(host.calls[-1][:2], ("userdel", [host.user]))
        host.assert_absent()

    def test_retries_finish_leftover_state_without_the_account(self):
        host = self.host(certificates=True)
        del host.accounts[host.user]
        host.groups[host.user] = grp.struct_group((host.user, "x", host.uid, []))
        for path in host.copies:
            path.unlink()
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        # The declared CA repeats the refresh that a crash may have skipped.
        self.assertEqual(host.tools(), ["curl", "trust", "groupdel", "rm"])
        host.assert_absent()

    def test_retry_without_the_account_ends_leftover_processes_first(self):
        host = self.host()
        del host.accounts[host.user]
        host.groups[host.user] = grp.struct_group((host.user, "x", host.uid, []))
        host.process(700, (165536,) * 4)
        host.fatal[700] = set()
        output, _ = host.invoke(expected=1)
        self.assertIn(
            f"- kill every process of UID {host.uid} and its sub-UID range 165536:65536,"
            " including running containers\n",
            output,
        )
        _, error = host.invoke("--yes", expected=1)
        self.assertIn(f"1 processes of {host.user} did not exit", error)
        self.assertEqual(host.calls, [])
        self.assertTrue(host.config.is_file())
        del host.fatal[700]
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        self.assertEqual(host.tools(), ["curl", "groupdel", "rm"])
        host.assert_absent()

    def test_refuses_before_any_mutation(self):
        for message, arrange in REFUSALS.items():
            with self.subTest(message=message):
                host = Host(self, certificates=True)
                try:
                    arrange(host)
                    before = host.f.snapshot()
                    accounts, groups = dict(host.accounts), dict(host.groups)
                    _, error = host.invoke("--yes", expected=1)
                    self.assertRegex(error, r"^runnerctl: ")
                    self.assertIn(message.rpartition(": ")[2], error)
                    self.assertEqual(host.f.snapshot(), before)
                    self.assertEqual((host.calls, host.signals), ([], []))
                    self.assertEqual((host.accounts, host.groups), (accounts, groups))
                finally:
                    host.close()

    def test_refuses_an_unreadable_ca_source_only_for_the_gitlab_phase(self):
        host = self.host(certificates=True)
        host.source.unlink()
        arguments = ("frontend", host.f.instance, host.platform)
        with self.assertRaisesRegex(operations.RunnerError, "cannot read declared public CA"):
            operations.remove(*arguments, yes=True, keep_gitlab=False)
        self.assertEqual(host.calls, [])
        self.assertEqual(operations.remove(*arguments, yes=True, keep_gitlab=True), "removed")
        self.assertNotIn("curl", host.tools())

    def test_ends_processes_that_hold_the_uid_or_its_range_anywhere(self):
        host = self.host()
        outside = 165536 + 65536
        host.process(700, (0, host.uid, 0, 0))
        host.process(701, (0, 0, host.uid, 0))
        host.process(702, (0, 0, 0, 0), tasks={702: (0, 0, 0, 0), 800: (0, 0, 0, host.uid)})
        host.process(703, (165536,) * 4)
        host.process(704, (outside - 1, 0, 0, 0))
        host.process(705, (host.uid,) * 4, state="Z")
        host.process(706, (outside,) * 4)
        host.process(707, (0,) * 4, tasks={900: (0,) * 4})
        # Entries that vanish during the scan: no status, a task without one, a non-directory.
        (host.proc / "708").mkdir()
        (host.proc / "707/task/901").mkdir()
        (host.proc / "709").write_text("")
        (host.proc / "uptime").write_text("")
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        # The zombie 705 counts until its parent reaps it; the fixture reaps on SIGTERM.
        self.assertEqual(
            sorted(host.signals), [(pid, signal.SIGTERM) for pid in (700, 701, 702, 703, 704, 705)]
        )
        self.assertEqual(host.sleeps, 0)
        self.assertTrue((host.proc / "706").is_dir())

    def test_waits_for_a_zombie_until_its_parent_reaps_it(self):
        host = self.host()
        host.process(705, (host.uid,) * 4, state="Z", ppid=4242)
        # Signals cannot end a zombie; only its parent's wait removes it.
        host.fatal[705] = set()
        host.on_sleep.append(lambda: shutil.rmtree(host.proc / "705"))
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        self.assertEqual(host.sleeps, 1)
        host.assert_absent()

    def test_a_zombie_that_stays_stops_removal_before_gitlab_and_names_its_parent(self):
        host = self.host()
        host.process(705, (165536,) * 4, state="Z", ppid=4242)
        host.process(706, (host.uid,) * 4)
        for pid in (705, 706):
            host.fatal[pid] = set()
        _, error = host.invoke("--yes", expected=1)
        self.assertIn(f"2 processes of {host.user} did not exit", error)
        self.assertIn("zombies 705 (parent 4242) wait for their parents", error)
        self.assertNotIn("706 (parent", error)
        self.assertNotIn("curl", host.tools())
        self.assertTrue(host.config.is_file())
        self.assertIn(host.user, host.accounts)
        self.assertTrue(host.home.is_dir())
        self.assertEqual(host.allocations().count(host.user), 2)

    def test_a_zombie_found_by_the_allocation_recheck_is_named(self):
        host = self.host()
        host.after["curl"] = lambda: host.process(705, (host.uid,) * 4, state="Z", ppid=4242)
        _, error = host.invoke("--yes", expected=1)
        self.assertIn(f"1 processes of {host.user} are still running", error)
        self.assertIn("zombies 705 (parent 4242)", error)
        self.assertEqual(host.allocations().count(host.user), 2)

    def test_only_a_zombie_without_live_threads_is_named_a_zombie(self):
        host = self.host()
        observed = removal._observe(host.f.instance, host.platform, host.paths)
        host.process(705, (host.uid,) * 4, state="Z", ppid=4242)
        # A thread-group leader that exited while another thread runs is a live process.
        host.process(711, (host.uid,) * 4, state="Z", ppid=4242)
        host.process(713, (host.uid,) * 4, state="D")
        shutil.move(host.proc / "713/task/713", host.proc / "711/task/713")
        shutil.rmtree(host.proc / "713")
        host.process(712, (host.uid,) * 4)
        # 999 vanished between the scan and the message.
        with self.assertRaises(operations.RunnerError) as failed:
            removal._raise_remaining(observed, [705, 711, 712, 999], "did not exit")
        message = str(failed.exception)
        self.assertTrue(message.startswith(f"3 processes of {host.user} did not exit"))
        self.assertIn("zombies 705 (parent 4242) wait", message)
        for pid in ("711", "712", "999"):
            self.assertNotIn(f"{pid} (parent", message)

    def test_processes_that_exit_after_the_last_poll_do_not_fail_removal(self):
        host = self.host()
        host.process(700, (host.uid,) * 4)
        host.fatal[700] = set()
        signals = []
        signaller = removal.signal_process.side_effect

        def last_kill_ends_it(pid, sig, matches):
            signaller(pid, sig, matches)
            signals.append(sig)
            if signals.count(signal.SIGKILL) == removal.POLLS // 2:
                shutil.rmtree(host.proc / str(pid))

        removal.signal_process.side_effect = last_kill_ends_it
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        self.assertEqual(host.sleeps, removal.POLLS - 1)
        host.assert_absent()

    def test_removal_that_leaves_the_account_never_reports_removed(self):
        host = self.host()
        host.inert = {"userdel"}
        output, error = host.invoke("--yes", expected=1)
        self.assertNotIn("removed", output)
        self.assertIn(f"Runner removal left account {host.user}", error)

    def test_a_mount_found_by_the_allocation_recheck_keeps_the_allocations(self):
        host = self.host()
        host.after["curl"] = lambda: _mount(host)
        _, error = host.invoke("--yes", expected=1)
        self.assertIn("mount under the Runner home", error)
        self.assertEqual(host.allocations().count(host.user), 2)
        self.assertIn(host.user, host.accounts)

    def test_a_pending_trust_marker_alone_refreshes_trust(self):
        host = self.host()
        host.f.owned(host.config.parent / ".trust.pending", b"", 0o600)
        output, _ = host.invoke(expected=1)
        self.assertIn("- refresh host trust\n", output)
        host.invoke("--yes")
        self.assertIn("trust", host.tools())
        host.assert_absent()

    def test_a_gitlab_url_with_a_trailing_slash_deletes_at_the_api_path(self):
        host = self.host()
        common = host.f.root / "common.toml"
        common.write_text(
            common.read_text().replace('"https://gitlab.example"', '"https://gitlab.example/"')
        )
        host.invoke("--yes")
        curl = next(args for tool, args, _ in host.calls if tool == "curl")
        self.assertEqual(curl[-1], "https://gitlab.example/api/v4/runners")

    def test_kills_processes_that_ignore_sigterm(self):
        host = self.host()
        host.process(700, (host.uid,) * 4)
        host.fatal[700] = {signal.SIGKILL}
        host.invoke("--yes")
        self.assertEqual(host.signals, [(700, signal.SIGTERM), (700, signal.SIGKILL)])
        self.assertEqual(host.sleeps, removal.POLLS // 2 + 1)
        host.assert_absent()

    def test_fails_when_processes_survive_every_poll(self):
        host = self.host()
        for pid in (700, 701):
            host.process(pid, (host.uid,) * 4)
            host.fatal[pid] = set()
        _, error = host.invoke("--yes", expected=1)
        self.assertIn(f"2 processes of {host.user} did not exit", error)
        self.assertEqual(host.sleeps, removal.POLLS - 1)
        self.assertEqual(host.signals.count((700, signal.SIGKILL)), removal.POLLS // 2)
        self.assertEqual(host.tools(), ["loginctl", "systemctl", "loginctl"])
        self.assertIn(host.user, host.accounts)
        self.assertNotEqual(host.allocations(), "")

    def test_default_signaller_never_signals_a_reused_or_vanished_pid(self):
        opened, closed, sent = [], [], []

        def pidfd_open(pid):
            if pid == 3:
                raise ProcessLookupError
            opened.append(100 + pid)
            return 100 + pid

        def send(descriptor, sig):
            sent.append((descriptor, sig))
            if descriptor == 104:
                raise ProcessLookupError

        with (
            mock.patch.object(removal.os, "pidfd_open", side_effect=pidfd_open),
            mock.patch.object(removal.os, "close", side_effect=closed.append),
            mock.patch.object(removal.signal, "pidfd_send_signal", side_effect=send),
        ):
            removal.signal_process(1, signal.SIGTERM, lambda _: True)
            removal.signal_process(2, signal.SIGKILL, lambda _: False)
            removal.signal_process(3, signal.SIGTERM, lambda _: True)
            removal.signal_process(4, signal.SIGTERM, lambda _: True)
            with self.assertRaises(RuntimeError):
                removal.signal_process(5, signal.SIGTERM, mock.Mock(side_effect=RuntimeError))
        self.assertEqual(sent, [(101, signal.SIGTERM), (104, signal.SIGTERM)])
        self.assertEqual(closed, opened)
        self.assertEqual(opened, [101, 102, 104, 105])

    def test_gitlab_failure_keeps_the_token_and_all_local_state(self):
        for result, message in (
            (subprocess.CompletedProcess([], 6, "000", ""), "curl exit code 6"),
            (subprocess.CompletedProcess([], 0, "403", ""), "HTTP status 403"),
            (subprocess.CompletedProcess([], 0, TOKEN, ""), "HTTP status unknown"),
        ):
            with self.subTest(message=message):
                host = Host(self, certificates=True)
                try:
                    host.curl = result
                    _, error = host.invoke("--yes", expected=1)
                    self.assertIn(message, error)
                    self.assertIn("rerun with --keep-gitlab only after you confirm", error)
                    self.assertEqual(host.tools()[3:], ["curl"])
                    self.assertTrue(host.config.is_file())
                    self.assertTrue(all(path.is_file() for path in host.copies))
                    self.assertIn(host.user, host.accounts)
                    self.assertTrue(host.home.is_dir())
                    self.assertEqual(host.allocations().count(host.user), 2)
                finally:
                    host.close()

    def test_deleted_runner_is_never_deleted_again(self):
        host = self.host()
        host.failing = {"userdel"}
        host.invoke("--yes", expected=1)
        self.assertFalse(host.config.exists())
        self.assertIn(host.user, host.accounts)
        host.failing.clear()
        host.calls.clear()
        output, _ = host.invoke("--yes")
        self.assertEqual(output, "frontend: removed\n")
        self.assertNotIn("curl", host.tools())
        host.assert_absent()

    def test_keep_gitlab_skips_the_deletion_even_for_an_invalid_registration(self):
        for registration in ("present", "invalid"):
            with self.subTest(registration=registration):
                host = Host(self)
                try:
                    host.registration = registration
                    output, _ = host.invoke("--yes", "--keep-gitlab")
                    self.assertEqual(output, "frontend: removed\n")
                    self.assertNotIn("curl", host.tools())
                    host.assert_absent()
                finally:
                    host.close()

    def test_native_runner_passes_stdin_and_keeps_it_out_of_diagnostics(self):
        secret = "synthetic-stdin-value"
        completed = subprocess.CompletedProcess(["/fixture/curl"], 7, "", "")
        with mock.patch.object(subprocess, "run", return_value=completed) as native:
            REAL_RUN(["/fixture/curl"], input=secret, check=False)
            self.assertEqual(native.call_args.kwargs["input"], secret)
            with self.assertRaises(operations.RunnerError) as failed:
                REAL_RUN(["/fixture/curl"], input=secret, public=True)
        self.assertNotIn(secret, str(failed.exception))
        expired = subprocess.TimeoutExpired(["/fixture/curl"], 300, output="", stderr="")
        with (
            mock.patch.object(subprocess, "run", side_effect=expired),
            self.assertRaises(operations.RunnerError) as timed_out,
        ):
            REAL_RUN(["/fixture/curl"], input=secret, public=True)
        self.assertNotIn(secret, str(timed_out.exception))


if __name__ == "__main__":
    unittest.main()
