"""Observe declared Runner policy without invoking native runtime commands."""

from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path
from typing import Any

from nix_adapter import Change, inspect_subordinate_range, regular_file
from nix_adapter.io import directory_fd

from .config import HostPaths
from .model import RunnerError, gitlab_hostname, render_registration_template, render_service


def inspect_account(instance: dict[str, Any]) -> pwd.struct_passwd | None:
    """Validate public account identity without creating accounts or reading passwords."""
    account = instance["account"]
    try:
        entry = pwd.getpwnam(account["user"])
    except KeyError:
        try:
            owner = pwd.getpwuid(account["uid"])
        except KeyError:
            owner = None
        if owner is not None:
            raise RunnerError(f"UID {account['uid']} is already owned by {owner.pw_name}") from None
        try:
            grp.getgrnam(account["user"])
        except KeyError:
            return None
        raise RunnerError(
            f"group already exists without its Runner account: {account['user']}"
        ) from None
    _check_account_identity(account, entry)
    return entry


def _check_account_identity(account: dict[str, Any], entry: pwd.struct_passwd) -> None:
    if entry.pw_uid != account["uid"]:
        raise RunnerError(f"{account['user']} already exists with a different UID")
    if entry.pw_dir != account["home"]:
        raise RunnerError(f"{account['user']} already exists with a different home")
    if grp.getgrgid(entry.pw_gid).gr_name != account["user"]:
        raise RunnerError(f"{account['user']} must use its dedicated primary group")
    if set(os.getgrouplist(entry.pw_name, entry.pw_gid)) - {entry.pw_gid}:
        raise RunnerError(f"{account['user']} must not have supplementary host roles")


def _info(path: Path) -> os.stat_result | None:
    try:
        with directory_fd(path.parent) as parent:
            return os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise RunnerError(f"cannot inspect managed Runner path: {path}") from None


def _owner(path: Path, info: os.stat_result, uid: int) -> None:
    if info.st_uid != uid:
        raise RunnerError(f"managed Runner path has a foreign owner: {path}")


def _metadata(info: os.stat_result, gid: int | None, mode: int | None) -> bool:
    return (gid is None or info.st_gid == gid) and (
        mode is None or stat.S_IMODE(info.st_mode) == mode
    )


def _directory(path: Path, uid: int, gid: int | None, mode: int | None) -> Change:
    info = _info(path)
    if info is None:
        return Change("+", f"prepare directory {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise RunnerError(f"managed Runner directory has an unsafe type: {path}")
    _owner(path, info, uid)
    if not _metadata(info, gid, mode):
        return Change("~", f"reconcile directory metadata {path}")
    return Change("=", f"directory metadata matches {path}")


def _file_info(path: Path, uid: int) -> os.stat_result | None:
    info = _info(path)
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RunnerError(f"managed Runner file has an unsafe type or hard links: {path}")
        _owner(path, info, uid)
    return info


def _public_text(path: Path, uid: int) -> str:
    try:
        with (
            directory_fd(path.parent) as parent,
            regular_file(parent, path.name, encoding="utf-8", preserve_newlines=True) as (
                stream,
                info,
            ),
        ):
            _owner(path, info, uid)
            return stream.read()
    except (OSError, UnicodeError):
        raise RunnerError(f"cannot read public Runner policy: {path}") from None


def _public_file(path: Path, uid: int, gid: int | None, mode: int, expected: str | None) -> Change:
    info = _file_info(path, uid)
    if info is None:
        return Change(
            "=" if expected is None else "+",
            f"public policy {'absent' if expected is None else 'needed'} {path}",
        )
    if expected is None:
        return Change("~", f"remove managed public policy {path}")
    if _public_text(path, uid) != expected or not _metadata(info, gid, mode):
        return Change("~", f"reconcile public policy {path}")
    return Change("=", f"public policy matches {path}")


def _runtime_config(path: Path, uid: int, gid: int | None) -> Change:
    info = _file_info(path, uid)
    if info is None:
        return Change("+", f"prepare runtime configuration {path}; registration is independent")
    if not _metadata(info, gid, 0o600):
        return Change("~", f"reconcile configuration metadata {path}; contents are unobserved")
    return Change(
        "-",
        f"configuration metadata matches {path}; policy and registration contents are unobserved",
    )


def _pending(path: Path, uid: int, gid: int | None) -> Change | None:
    info = _file_info(path, uid)
    if info is None:
        return None
    if not _metadata(info, gid, 0o600) or _public_text(path, uid) != "pending\n":
        raise RunnerError(f"invalid Runner pending marker: {path}")
    return Change("~", f"resume pending operation {path}")


def _certificates(
    instance: dict[str, Any], platform: dict[str, str], config: Path, uid: int, gid: int | None
) -> list[Change]:
    hostname = gitlab_hostname(instance)
    service = instance["runner"]["serviceName"]
    source = instance["gitlab"].get("caCertificate")
    expected = None
    if source is not None:
        try:
            expected = Path(source).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise RunnerError(f"cannot read declared public CA certificate: {source}") from None
    changes: list[Change] = []
    if expected is not None:
        for directory, owner, group, mode in (
            (config / "certs", uid, gid, 0o700),
            (Path(platform["caAnchorDirectory"]), 0, 0, 0o755),
            (Path(platform["containerCertsDirectory"]) / hostname, 0, 0, 0o755),
        ):
            changes.append(_directory(directory, owner, group, mode))
    changes.extend(
        [
            _public_file(config / "certs" / f"{hostname}.crt", uid, gid, 0o600, expected),
            _public_file(
                Path(platform["caAnchorDirectory"]) / f"runnerctl-{service}.crt",
                0,
                0,
                0o644,
                expected,
            ),
            _public_file(
                Path(platform["containerCertsDirectory"]) / hostname / f"runnerctl-{service}.crt",
                0,
                0,
                0o644,
                expected,
            ),
        ]
    )
    return changes


def inspect_policy(
    instance: dict[str, Any], platform: dict[str, str], *, paths: HostPaths
) -> list[Change]:
    """Report static observations and deferred runtime work without mutations."""
    account = instance["account"]
    entry = inspect_account(instance)
    uid = account["uid"]
    gid = entry.pw_gid if entry is not None else None
    home = paths.home_root / account["user"]
    home_state = _directory(home, uid, gid, None)
    if entry is not None and home_state.kind == "+":
        raise RunnerError(f"declared Runner account home is missing: {home}")
    changes = [
        Change("+" if entry is None else "=", f"account identity {account['user']}"),
        home_state,
    ]
    for path, key in ((paths.subuid, "subUid"), (paths.subgid, "subGid")):
        _file_info(path, 0)
        matches = inspect_subordinate_range(
            path, account["user"], account[key], aliases=(str(uid),)
        )
        changes.append(
            Change(
                "=" if matches else "~", f"subordinate allocation for {account['user']} in {path}"
            )
        )
    root = home / "gitlab-runner"
    config = root / "config"
    unit_dir = home / ".config/systemd/user"
    for directory in (root, config, root / "cache", home / ".config", unit_dir.parent, unit_dir):
        changes.append(_directory(directory, uid, gid, 0o700))
    changes.extend(
        [
            _public_file(
                config / "registration-template.toml",
                uid,
                gid,
                0o600,
                render_registration_template(instance),
            ),
            _public_file(
                unit_dir / f"{instance['runner']['serviceName']}.service",
                uid,
                gid,
                0o600,
                render_service(instance, platform),
            ),
            _runtime_config(config / "config.toml", uid, gid),
        ]
    )
    changes.extend(_certificates(instance, platform, config, uid, gid))
    for name in (".reconcile.pending", ".trust.pending"):
        pending = _pending(config / name, uid, gid)
        if pending is not None:
            changes.append(pending)
    changes.append(
        Change(
            "-",
            "runtime checks deferred to reconciliation: password lock, executables, network, GitLab health, services, images and containers",
        )
    )
    return changes
