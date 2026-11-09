"""Observe declared Runner policy without invoking native runtime commands."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

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


def path_info(path: Path) -> os.stat_result | None:
    """Inspect managed path metadata without following directory or leaf symlinks."""
    try:
        with directory_fd(path.parent) as parent:
            return os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise RunnerError(f"cannot inspect managed Runner path: {path}") from None


def require_owner(path: Path, info: os.stat_result, uid: int) -> None:
    """Reject a managed path whose owner differs from the declared UID."""
    if info.st_uid != uid:
        raise RunnerError(f"managed Runner path has a foreign owner: {path}")


def matches_metadata(info: os.stat_result, gid: int | None, mode: int | None) -> bool:
    """Compare declared group and mode with observed metadata."""
    return (gid is None or info.st_gid == gid) and (
        mode is None or stat.S_IMODE(info.st_mode) == mode
    )


def directory_change(path: Path, uid: int, gid: int | None, mode: int | None) -> Change:
    """Describe directory identity and metadata without creating or changing it."""
    info = path_info(path)
    if info is None:
        return Change("+", f"prepare directory {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise RunnerError(f"managed Runner directory has an unsafe type: {path}")
    require_owner(path, info, uid)
    if not matches_metadata(info, gid, mode):
        return Change("~", f"reconcile directory metadata {path}")
    return Change("=", f"directory metadata matches {path}")


def file_info(path: Path, uid: int) -> os.stat_result | None:
    """Inspect a single-link regular file and require its declared owner."""
    info = path_info(path)
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RunnerError(f"managed Runner file has an unsafe type or hard links: {path}")
        require_owner(path, info, uid)
    return info


def read_public_text(path: Path, uid: int) -> str:
    """Read only public policy through safe descriptors and recheck ownership."""
    try:
        with (
            directory_fd(path.parent) as parent,
            regular_file(parent, path.name, encoding="utf-8", preserve_newlines=True) as (
                stream,
                info,
            ),
        ):
            require_owner(path, info, uid)
            return stream.read()
    except (OSError, UnicodeError):
        raise RunnerError(f"cannot read public Runner policy: {path}") from None


def _public_file(path: Path, uid: int, gid: int | None, mode: int, expected: str | None) -> Change:
    info = file_info(path, uid)
    if info is None:
        return Change(
            "=" if expected is None else "+",
            f"public policy {'absent' if expected is None else 'needed'} {path}",
        )
    if expected is None:
        return Change("~", f"remove managed public policy {path}")
    if read_public_text(path, uid) != expected or not matches_metadata(info, gid, mode):
        return Change("~", f"reconcile public policy {path}")
    return Change("=", f"public policy matches {path}")


def _runtime_config(path: Path, uid: int, gid: int | None) -> Change:
    info = file_info(path, uid)
    if info is None:
        return Change("+", f"prepare runtime configuration {path}; registration is independent")
    if not matches_metadata(info, gid, 0o600):
        return Change("~", f"reconcile configuration metadata {path}; contents are unobserved")
    return Change(
        "-",
        f"configuration metadata matches {path}; policy and registration contents are unobserved",
    )


def _pending(path: Path, uid: int, gid: int | None) -> Change | None:
    info = file_info(path, uid)
    if info is None:
        return None
    if not matches_metadata(info, gid, 0o600) or read_public_text(path, uid) != "pending\n":
        raise RunnerError(f"invalid Runner pending marker: {path}")
    return Change("~", f"resume pending operation {path}")


@dataclass(frozen=True)
class PublicPolicy:
    """One exact public retirement target; registration content is excluded."""

    path: Path
    uid: int
    gid: int | None
    mode: int
    content: str | None


class RetirementIntent(TypedDict):
    """Public recovery state bound to one retirement declaration."""

    version: int
    phase: Literal["prepared", "services_stopped"]
    policy_digest: str
    trust: bool


def public_policy(
    instance: dict[str, Any], platform: dict[str, str], home: Path, gid: int | None
) -> dict[str, PublicPolicy]:
    """Describe exact public files without opening mixed registration config."""
    uid = instance["account"]["uid"]
    config = home / "gitlab-runner/config"
    hostname = gitlab_hostname(instance)
    service = instance["runner"]["serviceName"]
    source = instance["gitlab"].get("caCertificate")
    certificate = None
    if source is not None:
        try:
            certificate = Path(source).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise RunnerError(f"cannot read declared public CA certificate: {source}") from None
    return {
        "template": PublicPolicy(
            config / "registration-template.toml",
            uid,
            gid,
            0o600,
            render_registration_template(instance),
        ),
        "unit": PublicPolicy(
            home / ".config/systemd/user" / f"{service}.service",
            uid,
            gid,
            0o600,
            render_service(instance, platform),
        ),
        "manager_ca": PublicPolicy(
            config / "certs" / f"{hostname}.crt", uid, gid, 0o600, certificate
        ),
        "system_ca": PublicPolicy(
            Path(platform["caAnchorDirectory"]) / f"runnerctl-{service}.crt",
            0,
            0,
            0o644,
            certificate,
        ),
        "registry_ca": PublicPolicy(
            Path(platform["containerCertsDirectory"]) / hostname / f"runnerctl-{service}.crt",
            0,
            0,
            0o644,
            certificate,
        ),
    }


def retirement_digest(instance: dict[str, Any], policies: dict[str, PublicPolicy]) -> str:
    """Bind recovery to public identity, targets, metadata and expected contents."""
    document = {
        "account": instance["account"],
        "files": {
            name: [str(p.path), p.uid, p.gid, p.mode, p.content] for name, p in policies.items()
        },
    }
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()


def retirement_intent(
    path: Path, uid: int, gid: int | None, digest: str
) -> RetirementIntent | None:
    """Read a strict public recovery marker without observing registration."""
    info = file_info(path, uid)
    if info is None:
        return None
    if not matches_metadata(info, gid, 0o600):
        raise RunnerError(f"invalid Runner retirement marker metadata: {path}")
    try:
        parsed: object = json.loads(read_public_text(path, uid))
    except ValueError:
        raise RunnerError(f"invalid Runner retirement marker: {path}") from None
    if not isinstance(parsed, dict):
        raise RunnerError(f"invalid Runner retirement marker: {path}")
    value = cast("dict[str, Any]", parsed)
    if (
        set(value) != {"version", "phase", "policy_digest", "trust"}
        or type(value.get("version")) is not int
        or value["version"] != 1
        or value.get("phase") not in ("prepared", "services_stopped")
        or not isinstance(value.get("policy_digest"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["policy_digest"]) is None
        or type(value.get("trust")) is not bool
    ):
        raise RunnerError(f"invalid Runner retirement marker: {path}")
    if value["policy_digest"] != digest:
        raise RunnerError("unfinished Runner retirement requires its original declaration")
    return cast("RetirementIntent", value)


def _policy_change(policy: PublicPolicy) -> Change:
    return _public_file(policy.path, policy.uid, policy.gid, policy.mode, policy.content)


def _certificates(policies: dict[str, PublicPolicy]) -> list[Change]:
    copies = [policies[name] for name in ("manager_ca", "system_ca", "registry_ca")]
    changes: list[Change] = []
    if copies[0].content is not None:
        for policy in copies:
            changes.append(
                directory_change(
                    policy.path.parent, policy.uid, policy.gid, 0o700 if policy.uid != 0 else 0o755
                )
            )
    changes.extend(_policy_change(policy) for policy in copies)
    return changes


def inspect_policy(
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    paths: HostPaths,
    retirement_allowed: bool = True,
) -> list[Change]:
    """Report static observations and deferred runtime work without mutations."""
    account = instance["account"]
    entry = inspect_account(instance)
    uid = account["uid"]
    gid = entry.pw_gid if entry is not None else None
    home = paths.home_root / account["user"]
    home_state = directory_change(home, uid, gid, None)
    if entry is not None and home_state.kind == "+":
        raise RunnerError(f"declared Runner account home is missing: {home}")
    changes = [
        Change("+" if entry is None else "=", f"account identity {account['user']}"),
        home_state,
    ]
    for path, key in ((paths.subuid, "subUid"), (paths.subgid, "subGid")):
        file_info(path, 0)
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
        changes.append(directory_change(directory, uid, gid, 0o700))
    policies = public_policy(instance, platform, home, gid)
    changes.extend(_policy_change(policies[name]) for name in ("template", "unit"))
    changes.append(_runtime_config(config / "config.toml", uid, gid))
    changes.extend(_certificates(policies))
    retiring = retirement_intent(
        config / ".purge.pending", uid, gid, retirement_digest(instance, policies)
    )
    if retiring is not None:
        if not retirement_allowed:
            raise RunnerError("finish pending Runner retirement before reconciliation")
        changes.append(Change("~", f"resume pending retirement {config / '.purge.pending'}"))
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
