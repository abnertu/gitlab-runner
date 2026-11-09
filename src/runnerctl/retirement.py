"""Retire exact public Runner policy while retaining registrations and data."""

from __future__ import annotations

import json
import os
import pwd
import re
import sqlite3
import stat
import subprocess
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nix_adapter import atomic_write, inspect_subordinate_range, remove_managed_file
from nix_adapter.io import directory_fd

from . import inspection, operations
from .config import HostPaths
from .inspection import PublicPolicy, RetirementIntent
from .model import RunnerError


@dataclass(frozen=True)
class _Link:
    path: Path
    targets: tuple[str, ...]


@dataclass
class _Context:
    instance: dict[str, Any]
    platform: dict[str, str]
    paths: HostPaths
    entry: pwd.struct_passwd
    home: Path
    policies: dict[str, PublicPolicy]
    links: tuple[_Link, ...]
    pending: Path
    digest: str
    engine_checked: bool = False


def _check_policy(policy: PublicPolicy) -> bool:
    info = inspection.file_info(policy.path, policy.uid)
    if info is None:
        return False
    if (
        policy.content is None
        or not inspection.matches_metadata(info, policy.gid, policy.mode)
        or inspection.read_public_text(policy.path, policy.uid) != policy.content
    ):
        raise RunnerError(f"refuse drifted Runner retirement policy: {policy.path}")
    return True


def _link_exists(link: _Link, uid: int, gid: int) -> bool:
    if inspection.directory_change(link.path.parent, uid, gid, None).kind == "~":
        raise RunnerError(f"refuse drifted Runner enablement directory: {link.path.parent}")
    info = inspection.path_info(link.path)
    if info is None:
        return False
    inspection.require_owner(link.path, info, uid)
    if info.st_gid != gid:
        raise RunnerError(f"refuse drifted Runner enablement metadata: {link.path}")
    if not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise RunnerError(f"unsafe Runner enablement link: {link.path}")
    with directory_fd(link.path.parent) as parent:
        target = os.readlink(link.path.name, dir_fd=parent)
    if target not in link.targets:
        raise RunnerError(f"foreign Runner enablement target: {link.path}")
    return True


def _unlink(link: _Link, uid: int, gid: int) -> None:
    if _link_exists(link, uid, gid):
        with directory_fd(link.path.parent) as parent:
            owner = os.fstat(parent)
            inspection.require_owner(link.path.parent, owner, uid)
            if owner.st_gid != gid:
                raise RunnerError(f"Runner enablement directory changed: {link.path.parent}")
            os.unlink(link.path.name, dir_fd=parent)
            os.fsync(parent)


def _check_directories(context: _Context) -> None:
    uid, gid = context.entry.pw_uid, context.entry.pw_gid
    paths: dict[Path, tuple[int, int | None, int | None]] = {
        context.home: (uid, gid, None),
        context.home / "gitlab-runner": (uid, gid, 0o700),
        context.pending.parent: (uid, gid, 0o700),
        context.home / "gitlab-runner/cache": (uid, gid, 0o700),
        context.home / ".config": (uid, gid, 0o700),
        context.home / ".config/systemd": (uid, gid, 0o700),
        context.home / ".config/systemd/user": (uid, gid, 0o700),
    }
    paths.update({link.path.parent: (uid, gid, None) for link in context.links})
    for policy in context.policies.values():
        if policy.content is not None:
            paths[policy.path.parent] = (policy.uid, policy.gid, 0o700 if policy.uid else 0o755)
    for path, (owner, group, mode) in paths.items():
        if inspection.directory_change(path, owner, group, mode).kind == "~":
            raise RunnerError(f"refuse drifted Runner directory metadata: {path}")
    mixed = inspection.file_info(context.pending.parent / "config.toml", uid)
    if mixed is not None and not inspection.matches_metadata(mixed, gid, 0o600):
        raise RunnerError("refuse drifted Runner registration-file metadata")


def _context(
    instance: dict[str, Any], platform: dict[str, str], paths: HostPaths
) -> _Context | None:
    inspection.inspect_policy(instance, platform, paths=paths)
    account = instance["account"]
    entry = inspection.inspect_account(instance)
    home = paths.home_root / account["user"]
    policies = inspection.public_policy(instance, platform, home, entry.pw_gid if entry else None)
    present = [_check_policy(policy) for policy in policies.values()]
    pending = home / "gitlab-runner/config/.purge.pending"
    if entry is None:
        if (
            any(present)
            or inspection.path_info(home) is not None
            or inspection.path_info(pending) is not None
        ):
            raise RunnerError("Runner policy exists without its dedicated account")
        return None
    unit = policies["unit"].path
    vendor = platform["podmanSocketUnit"]
    links = (
        _Link(unit.parent / "default.target.wants" / unit.name, (str(unit), f"../{unit.name}")),
        _Link(unit.parent / "sockets.target.wants/podman.socket", (vendor,)),
    )
    context = _Context(
        instance,
        platform,
        paths,
        entry,
        home,
        policies,
        links,
        pending,
        inspection.retirement_digest(instance, policies),
    )
    _check_directories(context)
    for link in links:
        if (
            inspection.directory_change(link.path.parent, entry.pw_uid, entry.pw_gid, None).kind
            == "~"
        ):
            raise RunnerError(f"refuse drifted Runner enablement directory: {link.path.parent}")
        _link_exists(link, entry.pw_uid, entry.pw_gid)
    if inspection.path_info(unit.parent / "podman.socket") is not None:
        raise RunnerError("refuse a user override of the managed Podman socket")
    for path, key in ((paths.subuid, "subUid"), (paths.subgid, "subGid")):
        if not inspect_subordinate_range(
            path, entry.pw_name, account[key], aliases=(str(entry.pw_uid),)
        ):
            raise RunnerError(f"refuse drifted Runner subordinate allocation: {path}")
    return context


def _bus(context: _Context) -> None:
    path = context.paths.runtime / str(context.entry.pw_uid) / "bus"
    info = inspection.path_info(path)
    if info is None or not stat.S_ISSOCK(info.st_mode):
        raise RunnerError("Runner retirement requires its existing user bus")
    inspection.require_owner(path, info, context.entry.pw_uid)


def _database(path: Path, uid: int) -> None:
    try:
        with (
            directory_fd(path.parent) as parent,
            inspection.regular_file(parent, path.name) as (stream, info),
        ):
            inspection.require_owner(path, info, uid)
            if os.pread(stream.fileno(), 16, 0) != b"SQLite format 3\x00":
                raise RunnerError("Runner retirement requires initialized SQLite metadata")
            wal = inspection.file_info(path.with_name(path.name + "-wal"), uid)
            shm = inspection.file_info(path.with_name(path.name + "-shm"), uid)
            if inspection.path_info(path.with_name(path.name + "-journal")) is not None:
                raise RunnerError("Runner database needs recovery before retirement")
            if (wal is None) != (shm is None):
                raise RunnerError("Runner database has incomplete WAL readiness")
            if wal is None:
                uri = f"file:/proc/self/fd/{stream.fileno()}?mode=ro&immutable=1"
            else:
                uri = f"file:/proc/self/fd/{parent}/{path.name}?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=0.2)) as database:
                database.execute("PRAGMA query_only=ON")
                rows = database.execute("SELECT SchemaVersion FROM DBConfig LIMIT 2").fetchall()
                if rows != [(1,)]:
                    raise RunnerError("Runner database schema needs preparation before retirement")
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise RunnerError("Runner database changed during readiness inspection")
    except (OSError, sqlite3.Error):
        raise RunnerError("Runner retirement cannot confirm initialized SQLite metadata") from None


def _storage(context: _Context) -> tuple[Path, Path, Path]:
    root = context.home / ".local/share/containers/storage"
    runtime = context.paths.runtime / str(context.entry.pw_uid)
    runroot, temporary = runtime / "containers", runtime / "libpod/tmp"
    for path in (root, root / "libpod", root / "overlay", runroot, temporary):
        info = inspection.path_info(path)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise RunnerError(
                "Runner retirement requires initialized default overlay runtime/storage"
            )
        inspection.require_owner(path, info, context.entry.pw_uid)
    for path in (root / "db.sql", temporary / "alive"):
        if inspection.file_info(path, context.entry.pw_uid) is None:
            raise RunnerError("Runner retirement requires a live initialized SQLite engine")
    _database(root / "db.sql", context.entry.pw_uid)
    return root, runroot, temporary


def _podman(context: _Context, args: list[str]) -> subprocess.CompletedProcess[str]:
    root, runroot, temporary = _storage(context)
    prefix = [
        context.platform["env"],
        f"CONTAINERS_CONF={Path(__file__).with_name('retirement.conf')}",
        "CONTAINERS_STORAGE_CONF=/dev/null",
        context.platform["podman"],
        "--root",
        str(root),
        "--runroot",
        str(runroot),
        "--tmpdir",
        str(temporary),
        "--storage-driver",
        "overlay",
    ]
    if not context.engine_checked:
        version = operations.run_as(
            context.entry,
            [*prefix, "--version"],
            platform=context.platform,
            capture=True,
            check=False,
            public=True,
        )
        match = re.fullmatch(
            r"podman version (\d+)\.(\d+)\.(\d+)(?:[^\n]*)", version.stdout.strip()
        )
        if version.returncode != 0 or match is None or tuple(map(int, match.groups())) < (4, 8, 0):
            raise RunnerError(
                "Runner retirement requires Podman 4.8+ with initialized SQLite storage"
            )
        context.engine_checked = True
    return operations.run_as(
        context.entry,
        [*prefix, *args],
        platform=context.platform,
        capture=True,
        check=False,
        public=True,
        expected=(0, 1) if args[:2] == ["container", "exists"] else (0,),
    )


def _query(context: _Context, unit: str, *, socket: bool = False) -> dict[str, str]:
    keys = {
        "LoadState",
        "ActiveState",
        "FragmentPath",
        "DropInPaths",
        "Names",
        "NeedDaemonReload",
        "UnitFileState",
    }
    if socket:
        keys |= {"ExecStopPre", "ExecStopPost"}
    else:
        keys.add("MainPID")
    result = operations.user_systemctl(
        context.entry,
        context.platform,
        "show",
        unit,
        "--property=" + ",".join(sorted(keys)),
        query=True,
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise RunnerError("invalid Runner retirement unit query")
        values[key] = value
    if socket:
        # systemctl omits empty command arrays, even with --all.
        values = {"ExecStopPre": "", "ExecStopPost": ""} | values
    if result.returncode != 0 or set(values) != keys:
        raise RunnerError("cannot query Runner retirement units")
    return values


def _loaded(
    state: dict[str, str], unit: str, fragment: Path, *, allow_missing: bool, stale: bool = False
) -> None:
    if state["ActiveState"] not in {"active", "inactive", "failed"}:
        raise RunnerError("Runner retirement requires a stable unit state")
    names = state["Names"].split()
    if state["DropInPaths"] or (names != [unit] and (state["LoadState"] != "not-found" or names)):
        raise RunnerError("refuse Runner retirement unit aliases or drop-ins")
    missing = state["LoadState"] == "not-found" and allow_missing
    if not missing and (state["LoadState"] != "loaded" or state["FragmentPath"] != str(fragment)):
        raise RunnerError("refuse a foreign loaded Runner retirement unit")
    if missing and (state["ActiveState"] == "active" or state["FragmentPath"]):
        raise RunnerError("Runner retirement cannot identify a running missing unit")
    if state["NeedDaemonReload"] != "no" and not stale:
        raise RunnerError("Runner retirement unit sources changed after reload")
    if state["UnitFileState"] not in {"enabled", "disabled", "", "not-found"}:
        raise RunnerError("refuse unsupported Runner unit enablement")


def _states(
    context: _Context, *, stale: bool = False, unloaded_source: bool = False
) -> tuple[dict[str, str], dict[str, str]]:
    unit = context.policies["unit"].path
    service = _query(context, unit.name)
    socket = _query(context, "podman.socket", socket=True)
    _loaded(
        service,
        unit.name,
        unit,
        allow_missing=inspection.path_info(unit) is None or unloaded_source,
        stale=stale,
    )
    _loaded(
        socket,
        "podman.socket",
        Path(context.platform["podmanSocketUnit"]),
        allow_missing=False,
        stale=stale,
    )
    if socket["ExecStopPre"] or socket["ExecStopPost"]:
        raise RunnerError("refuse Podman socket stop hooks")
    return service, socket


def _manager_running(context: _Context) -> bool:
    exists = _podman(context, ["container", "exists", context.instance["runner"]["serviceName"]])
    if exists.returncode == 1:
        return False
    if exists.returncode != 0:
        raise RunnerError("cannot inspect the retiring Runner container")
    result = _podman(
        context,
        [
            "inspect",
            "--format",
            "{{json .State.Running}}",
            context.instance["runner"]["serviceName"],
        ],
    )
    if result.returncode != 0 or result.stdout.strip() not in {"true", "false"}:
        raise RunnerError("cannot inspect retiring Runner container state")
    return result.stdout.strip() == "true"


def _quiescent(context: _Context, states: tuple[dict[str, str], dict[str, str]]) -> None:
    if any(state["ActiveState"] == "active" for state in states) or _manager_running(context):
        raise RunnerError("Runner retirement has not stopped its service, socket and manager")
    if any(state["UnitFileState"] == "enabled" for state in states):
        raise RunnerError(
            "Runner units retain external enablement; preserve it for operator review"
        )


def _uses_database(context: _Context, state: dict[str, str]) -> None:
    pid = state["MainPID"]
    if re.fullmatch(r"[1-9][0-9]*", pid) is None:
        raise RunnerError("cannot identify the active Runner process")
    process = context.paths.proc_root / pid
    info = inspection.path_info(process)
    if info is None or not stat.S_ISDIR(info.st_mode):
        raise RunnerError("the active Runner process is unavailable")
    inspection.require_owner(process, info, context.entry.pw_uid)
    database = inspection.file_info(
        context.home / ".local/share/containers/storage/db.sql", context.entry.pw_uid
    )
    if database is None:
        raise RunnerError("the active Runner database is unavailable")
    with directory_fd(process / "fd") as descriptors:
        for name in os.listdir(descriptors):
            try:
                observed = os.stat(name, dir_fd=descriptors, follow_symlinks=True)
            except FileNotFoundError:
                continue
            if (observed.st_dev, observed.st_ino) == (database.st_dev, database.st_ino):
                return
    raise RunnerError("the active Runner uses an unverified storage database")


def _write_intent(context: _Context, intent: RetirementIntent) -> None:
    inspection.retirement_intent(
        context.pending, context.entry.pw_uid, context.entry.pw_gid, context.digest
    )
    atomic_write(
        context.pending,
        json.dumps(intent, sort_keys=True) + "\n",
        mode=0o600,
        uid=context.entry.pw_uid,
        gid=context.entry.pw_gid,
    )


def _stop(context: _Context, intent: RetirementIntent) -> None:
    for policy in context.policies.values():
        _check_policy(policy)
    operations.user_systemctl(context.entry, context.platform, "daemon-reload")
    service, socket = _states(context)
    _check_directories(context)
    for policy in context.policies.values():
        _check_policy(policy)
    if service["ActiveState"] == "active":
        _storage(context)
        _uses_database(context, service)
        if (
            operations.inspect_manager(
                context.instance,
                context.platform,
                context.entry,
                probe=lambda argv: _podman(context, argv[1:]),
            )
            != "matches-declaration"
        ):
            raise RunnerError("refuse a foreign or drifted active Runner manager")
        operations.user_systemctl(
            context.entry, context.platform, "stop", context.policies["unit"].path.name
        )
    if _manager_running(context):
        raise RunnerError("Runner manager remains running; preserve retirement intent")
    if socket["ActiveState"] == "active":
        operations.user_systemctl(context.entry, context.platform, "stop", "podman.socket")
    for link in context.links:
        _unlink(link, context.entry.pw_uid, context.entry.pw_gid)
    operations.user_systemctl(context.entry, context.platform, "daemon-reload")
    _quiescent(context, _states(context))
    intent["phase"] = "services_stopped"
    _write_intent(context, intent)


def _retire(context: _Context, intent: RetirementIntent) -> None:
    _quiescent(context, _states(context, stale=True))
    operations.user_systemctl(context.entry, context.platform, "daemon-reload")
    _quiescent(context, _states(context))
    _check_directories(context)
    for link in context.links:
        if _link_exists(link, context.entry.pw_uid, context.entry.pw_gid):
            raise RunnerError("Runner enablement changed after services stopped")
    for name, policy in context.policies.items():
        if _check_policy(policy):
            if name == "system_ca" and not intent["trust"]:
                intent["trust"] = True
                _write_intent(context, intent)
            remove_managed_file(policy.path)
    operations.user_systemctl(context.entry, context.platform, "daemon-reload")
    if intent["trust"]:
        operations.run([context.platform["trust"], "extract-compat"], public=True)
    _quiescent(context, _states(context))
    _check_directories(context)
    for policy in context.policies.values():
        if inspection.file_info(policy.path, policy.uid) is not None:
            raise RunnerError("Runner public policy reappeared during retirement")
    if any(
        _link_exists(link, context.entry.pw_uid, context.entry.pw_gid) for link in context.links
    ):
        raise RunnerError("Runner enablement reappeared during retirement")
    inspection.retirement_intent(
        context.pending, context.entry.pw_uid, context.entry.pw_gid, context.digest
    )
    remove_managed_file(context.pending)


def purge(instance: dict[str, Any], platform: dict[str, str], *, paths: HostPaths) -> bool:
    """Retire declared policy; return whether owned state changed."""
    operations.require_root()
    context = _context(instance, platform, paths)
    if context is None:
        return False
    _bus(context)
    intent: RetirementIntent | None = inspection.retirement_intent(
        context.pending, context.entry.pw_uid, context.entry.pw_gid, context.digest
    )
    present = any(_check_policy(policy) for policy in context.policies.values())
    linked = any(
        _link_exists(link, context.entry.pw_uid, context.entry.pw_gid) for link in context.links
    )
    _states(context, stale=True, unloaded_source=True)
    if intent is None and not present and not linked:
        _quiescent(context, _states(context))
        return False
    if inspection.path_info(context.pending.parent) is None:
        raise RunnerError("Runner retirement requires its existing private config directory")
    if intent is None:
        _storage(context)
        intent = RetirementIntent(
            version=1,
            phase="prepared",
            policy_digest=context.digest,
            trust=inspection.path_info(context.policies["system_ca"].path) is not None,
        )
        _write_intent(context, intent)
    if intent["phase"] == "prepared":
        _stop(context, intent)
    _retire(context, intent)
    return True
