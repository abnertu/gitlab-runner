"""Remove one declared Runner instance completely.

Removal ends the account's processes, deletes the GitLab runner and removes
the CA copies, subordinate allocations, linger, account, group and home.
"""

from __future__ import annotations

import grp
import os
import pwd
import re
import signal
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from nix_adapter import (
    inspect_subordinate_range,
    remove_managed_file,
    remove_subordinate_range,
    subordinate_allocation,
)

from . import inspection, operations
from .config import HostPaths
from .model import RunnerError, gitlab_hostname

Result = Literal["removed", "unchanged", "preview"]
Matcher = Callable[[int], bool]
Signaller = Callable[[int, int, Matcher], None]

POLLS = 30
"""Process-exit polls, one second apart; SIGKILL starts after half of them."""

KEEP_ADVICE = "rerun with --keep-gitlab only after you confirm that the runner is gone in GitLab"

sleep = time.sleep

_VANISHED = (FileNotFoundError, ProcessLookupError, NotADirectoryError)
_SUBORDINATE = (("subuid", "subUid"), ("subgid", "subGid"))


def signal_process(pid: int, sig: int, matches: Matcher) -> None:
    """Signal `pid` through a pidfd, only if `matches` still holds for it.

    The recheck runs after the pidfd is open, so a reused PID is never signaled.
    """
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        if matches(pid):
            signal.pidfd_send_signal(descriptor, sig)
    except ProcessLookupError:
        pass
    finally:
        os.close(descriptor)


@dataclass
class _Observation:
    instance: dict[str, Any]
    platform: dict[str, str]
    paths: HostPaths
    user: str
    uid: int
    home: Path
    config: Path
    entry: pwd.struct_passwd | None
    group: int | None
    home_present: bool
    allocations: dict[Path, dict[str, int]]
    linger: Path | None
    copies: list[Path]
    registration: Literal["present", "absent", "invalid"]
    metadata: dict[str, str] = field(repr=False)
    trust: bool

    @property
    def gitlab(self) -> bool:
        """Whether the GitLab phase holds a registration."""
        return self.registration != "absent"

    @property
    def left(self) -> bool:
        """Whether any host state of the instance remains."""
        return bool(
            self.entry is not None
            or self.group is not None
            or self.home_present
            or self.allocations
            or self.linger is not None
            or self.copies
        )


def _account(account: dict[str, Any]) -> pwd.struct_passwd | None:
    user, uid = account["user"], account["uid"]
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        try:
            owner = pwd.getpwuid(uid)
        except KeyError:
            return None
        raise RunnerError(f"UID {uid} is owned by {owner.pw_name}") from None
    if entry.pw_uid != uid:
        raise RunnerError(f"{user} exists with a different UID")
    if entry.pw_dir != account["home"]:
        raise RunnerError(f"{user} exists with a different home")
    return entry


def _group(user: str, uid: int, entry: pwd.struct_passwd | None) -> int | None:
    try:
        group = grp.getgrnam(user)
    except KeyError:
        return None
    advice = f"inspect group {user} and run groupdel by hand"
    if group.gr_mem:
        raise RunnerError(f"group {user} has members; {advice}")
    if any(e.pw_gid == group.gr_gid and e.pw_name != user for e in pwd.getpwall()):
        raise RunnerError(f"group {user} is the primary group of another account; {advice}")
    if group.gr_gid != (entry.pw_gid if entry is not None else uid):
        raise RunnerError(f"group {user} is not the Runner account's own group; {advice}")
    return group.gr_gid


def _home(home: Path, uid: int) -> bool:
    info = inspection.path_info(home)
    if info is None:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise RunnerError(f"Runner home has an unsafe type: {home}")
    inspection.require_owner(home, info, uid)
    return True


def _mounted(paths: HostPaths, home: Path) -> None:
    # `/proc/self` is a symlink, so the no-follow helpers cannot read it.
    try:
        with open(paths.proc_root / "self/mountinfo", encoding="utf-8", errors="replace") as file:
            lines = file.read().splitlines()
    except OSError:
        raise RunnerError("cannot read the mount table") from None
    for line in lines:
        fields = line.split()
        if len(fields) < 5:
            continue
        point = Path(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4]))
        if point == home or home in point.parents:
            raise RunnerError(f"refuse removal with a mount under the Runner home: {point}")


def _allocations(account: dict[str, Any], paths: HostPaths) -> dict[Path, dict[str, int]]:
    user, aliases = account["user"], (str(account["uid"]),)
    found: dict[Path, dict[str, int]] = {}
    for attribute, key in _SUBORDINATE:
        path: Path = getattr(paths, attribute)
        inspection.file_info(path, 0)
        allocation = subordinate_allocation(path, user, aliases=aliases)
        if allocation is None:
            continue
        if not inspect_subordinate_range(path, user, account[key], aliases=aliases):
            raise RunnerError(f"refuse drifted Runner subordinate allocation: {path}")
        found[path] = allocation
    return found


def _copy_paths(instance: dict[str, Any], platform: dict[str, str]) -> list[Path]:
    name = f"runnerctl-{instance['runner']['serviceName']}.crt"
    return [
        Path(platform["caAnchorDirectory"]) / name,
        Path(platform["containerCertsDirectory"]) / gitlab_hostname(instance) / name,
    ]


def _registration(
    config: Path, uid: int
) -> tuple[Literal["present", "absent", "invalid"], dict[str, str]]:
    if inspection.file_info(config, uid) is None:
        return "absent", {}
    try:
        metadata = operations.registration_metadata(config)
    except RunnerError:
        return "invalid", {}
    return ("present", metadata) if metadata else ("absent", {})


def _observe(instance: dict[str, Any], platform: dict[str, str], paths: HostPaths) -> _Observation:
    account = instance["account"]
    user, uid = account["user"], account["uid"]
    home = paths.home_root / user
    directory = home / "gitlab-runner/config"
    entry = _account(account)
    group = _group(user, uid, entry)
    home_present = _home(home, uid)
    allocations = _allocations(account, paths)
    linger = paths.linger / user
    lingering = inspection.file_info(linger, 0) is not None
    _mounted(paths, home)
    copies = [path for path in _copy_paths(instance, platform) if inspection.file_info(path, 0)]
    registration, metadata = _registration(directory / "config.toml", uid)
    markers = [
        inspection.file_info(directory / name, uid) is not None
        for name in (".trust.pending", ".purge.pending")
    ]
    return _Observation(
        instance,
        platform,
        paths,
        user,
        uid,
        home,
        directory / "config.toml",
        entry,
        group,
        home_present,
        allocations,
        linger if lingering else None,
        copies,
        registration,
        metadata,
        bool(copies or any(markers) or instance["gitlab"].get("caCertificate")),
    )


def _require(observed: _Observation, *, keep_gitlab: bool) -> None:
    """Refuse work that cannot complete, before any mutation."""
    delete = observed.registration == "present" and not keep_gitlab
    if observed.registration == "invalid" and not keep_gitlab:
        raise RunnerError(f"dedicated Runner registration is invalid; {KEEP_ADVICE}")
    source = observed.instance["gitlab"].get("caCertificate")
    if delete and source:
        try:
            with open(source, "rb") as file:
                file.read(1)
        except OSError:
            raise RunnerError(f"cannot read declared public CA certificate: {source}") from None
    needed = {
        "loginctl": observed.entry is not None,
        "systemctl": observed.entry is not None,
        "curl": delete,
        "trust": observed.trust,
        "userdel": observed.entry is not None,
        "groupdel": observed.group is not None,
        "rm": observed.home_present,
    }
    for name, required in needed.items():
        if required and not Path(observed.platform[name]).is_file():
            raise RunnerError(f"required host executable is missing: {observed.platform[name]}")


def _process_items(observed: _Observation) -> list[str]:
    scope = f"UID {observed.uid}"
    allocation = observed.allocations.get(observed.paths.subuid)
    if allocation is not None:
        scope += f" and its sub-UID range {allocation['start']}:{allocation['count']}"
    kill = f"kill every process of {scope}, including running containers"
    if observed.entry is not None:
        return [f"stop the user manager and {kill}"]
    # A retry after the account is gone still ends the leftover processes.
    return [kill] if _scan(observed, _matcher(observed)) else []


def _items(observed: _Observation, *, keep_gitlab: bool) -> list[str]:
    items = _process_items(observed)
    if observed.gitlab and keep_gitlab:
        items.append("keep the GitLab runner (--keep-gitlab)")
    elif observed.gitlab:
        items.append(f"delete GitLab runner {observed.metadata.get('id', '(ID unknown)')}")
        items.append(f"delete config {observed.config}")
    items.extend(f"remove CA copy {path}" for path in observed.copies)
    if observed.trust:
        items.append("refresh host trust")
    items.extend(
        f"remove sub-ID allocation {path} {value['start']}:{value['count']}"
        for path, value in observed.allocations.items()
    )
    if observed.linger is not None:
        items.append(f"remove linger {observed.linger}")
    if observed.entry is not None:
        items.append(f"delete account {observed.user}")
    if observed.group is not None:
        items.append(f"delete group {observed.user}")
    if observed.home_present:
        items.append(f"delete home {observed.home}")
    return items


def _status(path: Path) -> dict[str, str]:
    """The first value of each `/proc` status field."""
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name, _, value = line.partition(":")
        fields[name] = value.strip()
    return fields


def _status_matches(path: Path, wanted: Matcher) -> bool:
    # A zombie still holds its UID, and `userdel` refuses a busy account.
    uids = _status(path).get("Uid", "").split()
    return any(wanted(int(value)) for value in uids if value.isdigit())


def _zombie_parent(proc_root: Path, pid: int) -> int | None:
    """The parent PID of a zombie `pid`, or `None` for a live or vanished process.

    A thread-group leader can exit while its other threads run; that process is live.
    """
    base = proc_root / str(pid)
    try:
        fields = _status(base / "status")
        if not fields.get("State", "").startswith("Z"):
            return None
        tasks = os.listdir(base / "task")
    except _VANISHED:
        return None
    for task in tasks:
        try:
            if not _status(base / "task" / task / "status").get("State", "").startswith("Z"):
                return None
        except _VANISHED:
            continue
    parent = fields.get("PPid", "")
    return int(parent) if parent.isdigit() else None


def _raise_remaining(observed: _Observation, pids: list[int], what: str) -> None:
    """Fail for the processes of `pids` that still exist; name each zombie with its parent.

    A PID that exited after the scan, or now belongs to another process, is left out.
    With none left, nothing fails.
    """
    matches = _matcher(observed)
    pids = [pid for pid in pids if matches(pid)]
    if not pids:
        return
    message = f"{len(pids)} processes of {observed.user} {what}"
    zombies = [
        f"{pid} (parent {parent})"
        for pid in pids
        if (parent := _zombie_parent(observed.paths.proc_root, pid)) is not None
    ]
    if zombies:
        message += f"; zombies {', '.join(zombies)} wait for their parents to reap them"
    raise RunnerError(message)


def _process_matches(proc_root: Path, pid: int, wanted: Matcher) -> bool:
    """Whether a live process or one of its tasks holds a wanted UID."""
    base = proc_root / str(pid)
    try:
        if _status_matches(base / "status", wanted):
            return True
        tasks = sorted(os.listdir(base / "task"))
    except _VANISHED:
        return False
    for task in tasks:
        try:
            if _status_matches(base / "task" / task / "status", wanted):
                return True
        except _VANISHED:
            continue
    return False


def _matcher(observed: _Observation) -> Matcher:
    allocation = observed.allocations.get(observed.paths.subuid)
    start = allocation["start"] if allocation else 0
    end = start + allocation["count"] if allocation else 0
    proc_root, runner = observed.paths.proc_root, observed.uid

    def wanted(uid: int) -> bool:
        return uid == runner or start <= uid < end

    return lambda pid: _process_matches(proc_root, pid, wanted)


def _scan(observed: _Observation, matches: Matcher) -> list[int]:
    try:
        entries = os.listdir(observed.paths.proc_root)
    except OSError:
        raise RunnerError("cannot read the process table") from None
    return [int(entry) for entry in entries if entry.isdigit() and matches(int(entry))]


def _terminate(
    observed: _Observation, pause: Callable[[float], None], signaller: Signaller
) -> None:
    matches = _matcher(observed)
    pending = _scan(observed, matches)
    for pid in pending:
        signaller(pid, signal.SIGTERM, matches)
    for poll in range(POLLS):
        if poll:
            pause(1)
        pending = _scan(observed, matches)
        if not pending:
            return
        if poll >= POLLS // 2:
            for pid in pending:
                signaller(pid, signal.SIGKILL, matches)
    _raise_remaining(observed, pending, "did not exit")


def _stop(observed: _Observation, pause: Callable[[float], None], signaller: Signaller) -> None:
    platform, user = observed.platform, observed.user
    operations.run([platform["loginctl"], "disable-linger", user], public=True)
    operations.run([platform["systemctl"], "stop", f"user@{observed.uid}.service"], public=True)
    # A user without sessions is not an error.
    operations.run([platform["loginctl"], "terminate-user", user], check=False)
    _terminate(observed, pause, signaller)


def _delete_runner(observed: _Observation) -> None:
    gitlab = observed.instance["gitlab"]
    argv = [
        observed.platform["curl"],
        "--disable",
        "--silent",
        "--show-error",
        "--request",
        "DELETE",
        "--data-urlencode",
        "token@-",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
    ]
    if gitlab.get("caCertificate"):
        argv.extend(["--cacert", gitlab["caCertificate"]])
    argv.append(gitlab["url"].rstrip("/") + "/api/v4/runners")
    result = operations.run(argv, input=observed.metadata["token"], capture=True, check=False)
    if result.returncode != 0:
        raise RunnerError(
            f"GitLab runner deletion failed with curl exit code {result.returncode}; {KEEP_ADVICE}"
        )
    code = (result.stdout or "").strip()
    if code != "204":
        shown = code if re.fullmatch(r"[0-9]{3}", code) else "unknown"
        raise RunnerError(f"GitLab runner deletion failed with HTTP status {shown}; {KEEP_ADVICE}")
    # The runner is gone, so a retry must not send its token again.
    remove_managed_file(observed.config)


def _remove_trust(observed: _Observation) -> None:
    for path in observed.copies:
        remove_managed_file(path)
    if observed.trust:
        operations.run([observed.platform["trust"], "extract-compat"], public=True)


def _remove_allocations(observed: _Observation) -> None:
    _mounted(observed.paths, observed.home)
    _raise_remaining(observed, _scan(observed, _matcher(observed)), "are still running")
    account = observed.instance["account"]
    for attribute, key in _SUBORDINATE:
        path: Path = getattr(observed.paths, attribute)
        if path in observed.allocations:
            remove_subordinate_range(
                path, observed.user, account[key], aliases=(str(observed.uid),)
            )


def _remove_identity(observed: _Observation) -> None:
    platform, user = observed.platform, observed.user
    if observed.entry is not None:
        argv = [platform["userdel"], "--remove", user]
        if not observed.home_present:
            argv.remove("--remove")
        operations.run(argv, public=True)
    remove_managed_file(observed.paths.linger / user)
    if observed.group is not None:
        try:
            group = grp.getgrnam(user)
        except KeyError:
            group = None
        if group is not None and group.gr_gid == observed.group:
            operations.run([platform["groupdel"], user], public=True)
    if _home(observed.home, observed.uid):
        _mounted(observed.paths, observed.home)
        operations.run(
            [platform["rm"], "--recursive", "--one-file-system", "--", str(observed.home)],
            public=True,
        )


def _verify(observed: _Observation) -> None:
    after = _observe(observed.instance, observed.platform, observed.paths)
    remaining = {
        f"account {after.user}": after.entry is not None,
        f"group {after.user}": after.group is not None,
        f"home {after.home}": after.home_present,
        "subordinate allocation": bool(after.allocations),
        f"linger {after.paths.linger / after.user}": after.linger is not None,
        "CA copy": bool(after.copies),
    }
    for item, present in remaining.items():
        if present:
            raise RunnerError(f"Runner removal left {item}")


def remove(
    name: str,
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    paths: HostPaths,
    yes: bool,
    keep_gitlab: bool,
    pause: Callable[[float], None],
    signaller: Signaller,
) -> Result:
    """Remove instance `name`; without `yes`, print the removal items only.

    Every refusal comes before the first mutation. Each step is idempotent, so
    a failed removal repeats from the observation.
    """
    operations.require_root()
    observed = _observe(instance, platform, paths)
    if not observed.left:
        return "unchanged"
    _require(observed, keep_gitlab=keep_gitlab)
    if not yes:
        for item in _items(observed, keep_gitlab=keep_gitlab):
            print(f"- {item}")
        print(f"rerun with --yes to remove {name}", file=sys.stderr)
        return "preview"
    if observed.entry is not None:
        _stop(observed, pause, signaller)
    else:
        _terminate(observed, pause, signaller)
    if observed.registration == "present" and not keep_gitlab:
        _delete_runner(observed)
    _remove_trust(observed)
    _remove_allocations(observed)
    _remove_identity(observed)
    _verify(observed)
    return "removed"
