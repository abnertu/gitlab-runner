#!/usr/bin/env python3

"""Converge dedicated rootless Podman GitLab Runner instances."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime
import tomllib
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
from typing import Any, Callable


from dataclasses import dataclass
from runner_model import (
    RunnerError,
    validate_instances,
    gitlab_hostname,
    render_registration_template,
    render_config,
    render_service,
    manager_matches,
)
from nix_adapter import (
    atomic_write,
    ensure_directory,
    ensure_subordinate_range,
    operation_lock as _operation_lock,
    read_managed,
    remove_managed_file,
)
from nix_adapter.progress import Progress


@dataclass(frozen=True)
class HostPaths:
    """Private filesystem seam; production paths cannot be overridden by CLI."""

    subuid: Path = Path("/etc/subuid")
    subgid: Path = Path("/etc/subgid")
    runtime: Path = Path("/run/user")


def run(
    argv: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
    timeout: float = 300,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RunnerError(f"command timed out after {timeout}s: {argv[0]}") from None
    if check and result.returncode != 0:
        raise RunnerError(f"command failed with exit code {result.returncode}: {argv[0]}")
    return result


@contextmanager
def operation_lock(path: Path = Path("/run/lock/nix-config-runner.lock")):
    """Serialize our mutations across instances, including shared sub-ID files."""
    with _operation_lock(path, label="Runner operation"):
        yield


@contextmanager
def progress_task(scope: str, label: str, progress: Progress | None = None):
    """Run a lifecycle boundary and close an owned renderer safely."""
    owner = progress is None
    current = progress or Progress(scope, verbose=False)
    try:
        with current.task(label):
            yield current
    finally:
        if owner:
            try:
                current.close()
            except Exception:
                pass


def require_root() -> None:
    if os.geteuid() != 0:
        raise RunnerError("this command must run as root")


def select_instance(instances: dict[str, Any], name: str) -> dict[str, Any]:
    try:
        return instances[name]
    except KeyError as error:
        available = ", ".join(sorted(instances))
        raise RunnerError(f"unknown instance {name}; available: {available}") from error


def required_interface_is_up(name: str | None, ip_path: str) -> None:
    if name is None:
        return
    result = run([ip_path, "-json", "link", "show", "dev", name], capture=True, check=False)
    if result.returncode != 0:
        raise RunnerError(f"required network interface is missing: {name}")
    links = json.loads(result.stdout)
    if len(links) != 1 or "UP" not in links[0].get("flags", []):
        raise RunnerError(f"required network interface is not up: {name}")


def ensure_account(instance: dict[str, Any], platform: dict[str, str]) -> pwd.struct_passwd:
    account = instance["account"]
    try:
        entry = pwd.getpwnam(account["user"])
    except KeyError:
        try:
            owner = pwd.getpwuid(account["uid"])
        except KeyError:
            owner = None
        if owner is not None:
            raise RunnerError(f"UID {account['uid']} is already owned by {owner.pw_name}")
        run(
            [
                platform["useradd"],
                "--create-home",
                "--home-dir",
                account["home"],
                "--shell",
                "/bin/bash",
                "--uid",
                str(account["uid"]),
                "--user-group",
                account["user"],
            ]
        )
        run([platform["usermod"], "--lock", account["user"]])
        entry = pwd.getpwnam(account["user"])

    if entry.pw_uid != account["uid"]:
        raise RunnerError(f"{account['user']} already exists with a different UID")
    if entry.pw_dir != account["home"]:
        raise RunnerError(f"{account['user']} already exists with a different home")
    if grp.getgrgid(entry.pw_gid).gr_name != account["user"]:
        raise RunnerError(f"{account['user']} must use its dedicated primary group")
    supplementary_groups = set(os.getgrouplist(entry.pw_name, entry.pw_gid)) - {entry.pw_gid}
    if supplementary_groups:
        raise RunnerError(f"{account['user']} must not have supplementary host roles")
    password = run([platform["passwd"], "--status", entry.pw_name], capture=True)
    fields = password.stdout.split()
    if len(fields) < 2 or fields[0] != entry.pw_name or fields[1] != "L":
        raise RunnerError(
            "Runner account must have a locked password; reconcile ownership manually"
        )
    return entry


def registration_metadata(config_path: Path) -> dict[str, str]:
    try:
        document = tomllib.loads(read_managed(config_path))
    except (ValueError, UnicodeError):
        raise RunnerError("dedicated Runner config is invalid TOML") from None
    registrations = document.get("runners", [])
    if not isinstance(registrations, list):
        raise RunnerError("dedicated Runner registrations must be a list")
    if len(registrations) > 1:
        raise RunnerError("dedicated Runner config contains multiple registrations")
    if not registrations:
        return {}
    runner = registrations[0]
    if (
        not isinstance(runner, dict)
        or not isinstance(runner.get("token"), str)
        or not runner["token"]
    ):
        raise RunnerError("dedicated Runner config contains an incomplete registration")
    metadata = {"token": runner["token"]}
    if "id" in runner:
        if type(runner["id"]) is not int or runner["id"] <= 0:
            raise RunnerError("dedicated Runner registration has an invalid ID")
        metadata["id"] = str(runner["id"])
    for field in ("token_obtained_at", "token_expires_at"):
        if field in runner:
            value = runner[field]
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise RunnerError("dedicated Runner registration has an invalid timestamp")
            metadata[field] = value.isoformat().replace("+00:00", "Z")
    return metadata


def run_as(
    entry: pwd.struct_passwd,
    argv: list[str],
    *,
    platform: dict[str, str],
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    runtime_dir = f"/run/user/{entry.pw_uid}"
    return run(
        [
            platform["runuser"],
            "--user",
            entry.pw_name,
            "--",
            platform["env"],
            "--ignore-environment",
            "PATH=/usr/bin",
            f"HOME={entry.pw_dir}",
            f"XDG_RUNTIME_DIR={runtime_dir}",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime_dir}/bus",
            *argv,
        ],
        capture=capture,
        check=check,
    )


def ensure_directories(entry: pwd.struct_passwd) -> tuple[Path, Path, Path]:
    root = Path(entry.pw_dir) / "gitlab-runner"
    config_dir = root / "config"
    cache_dir = root / "cache"
    unit_dir = Path(entry.pw_dir) / ".config/systemd/user"
    for path in (
        root,
        config_dir,
        cache_dir,
        Path(entry.pw_dir) / ".config",
        unit_dir.parent,
        unit_dir,
    ):
        ensure_directory(path, mode=0o700, uid=entry.pw_uid, gid=entry.pw_gid)
    return config_dir, cache_dir, unit_dir


def wait_for_path(path: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.25)
    raise RunnerError(f"timed out waiting for required runtime path: {path}")


def reconcile_ca(
    instance: dict[str, Any],
    entry: pwd.struct_passwd,
    config_dir: Path,
    platform: dict[str, str],
    before_change: Callable[[], None] | None = None,
) -> bool:
    hostname = gitlab_hostname(instance)
    service_name = instance["runner"]["serviceName"]
    manager_certificate = config_dir / "certs" / f"{hostname}.crt"
    system_certificate = Path(platform["caAnchorDirectory"]) / f"nix-config-{service_name}.crt"
    registry_certificate = (
        Path(platform["containerCertsDirectory"]) / hostname / f"nix-config-{service_name}.crt"
    )
    source = instance["gitlab"].get("caCertificate")
    changed = False
    system_trust_changed = False
    trust_pending = config_dir / ".trust.pending"

    def mark_trust():
        if before_change is not None:
            before_change()
        atomic_write(trust_pending, "pending\n", mode=0o600, uid=entry.pw_uid, gid=entry.pw_gid)

    if source:
        source_path = Path(source)
        if source_path.suffix.lower() not in {".crt", ".pem"} or not source_path.is_file():
            raise RunnerError("GitLab CA certificate must be a readable .crt or .pem file")
        content = source_path.read_text()
        ensure_directory(manager_certificate.parent, mode=0o700, uid=entry.pw_uid, gid=entry.pw_gid)
        for directory in (system_certificate.parent, registry_certificate.parent):
            ensure_directory(directory, mode=0o755, uid=0, gid=0)
        manager_changed = atomic_write(
            manager_certificate,
            content,
            mode=0o600,
            uid=entry.pw_uid,
            gid=entry.pw_gid,
            before_change=before_change,
        )
        system_trust_changed = atomic_write(
            system_certificate,
            content,
            mode=0o644,
            uid=0,
            gid=0,
            before_change=mark_trust,
        )
        registry_changed = atomic_write(
            registry_certificate,
            content,
            mode=0o644,
            uid=0,
            gid=0,
            before_change=before_change,
        )
        changed = manager_changed or system_trust_changed or registry_changed
    else:
        manager_changed = remove_managed_file(manager_certificate, before_change)
        system_trust_changed = remove_managed_file(system_certificate, mark_trust)
        registry_changed = remove_managed_file(registry_certificate, before_change)
        changed = manager_changed or system_trust_changed or registry_changed
    if system_trust_changed or trust_pending.exists():
        run([platform["trust"], "extract-compat"])
        remove_managed_file(trust_pending)
    return changed


def verify_rootless_podman(
    entry: pwd.struct_passwd,
    platform: dict[str, str],
) -> None:
    podman_path = platform["podman"]
    version_result = run_as(entry, [podman_path, "--version"], platform=platform, capture=True)
    version_match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_result.stdout)
    if version_match is None or tuple(map(int, version_match.groups())) < (4, 2, 0):
        raise RunnerError("rootless Podman 4.2.0 or newer is required")
    info_result = run_as(
        entry,
        [podman_path, "info", "--format", "json"],
        platform=platform,
        capture=True,
    )
    info = json.loads(info_result.stdout)
    if not info.get("host", {}).get("security", {}).get("rootless", False):
        raise RunnerError(f"Podman is not rootless for {entry.pw_name}")
    if info.get("host", {}).get("networkBackend") != "netavark":
        raise RunnerError(f"Podman does not use netavark for {entry.pw_name}")


def verify_aardvark(platform: dict[str, str]) -> None:
    result = run([platform["aardvarkDns"], "--version"], capture=True)
    version = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout + result.stderr)
    if version is None or tuple(map(int, version.groups())) <= (1, 10, 0):
        raise RunnerError("aardvark-dns newer than 1.10.0 is required")


def health_command(instance: dict[str, Any], platform: dict[str, str]) -> list[str]:
    command = [
        platform["curl"],
        "--fail",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
    ]
    ca_certificate = instance["gitlab"].get("caCertificate")
    if ca_certificate:
        command.extend(["--cacert", ca_certificate])
    command.append(instance["gitlab"]["healthUrl"])
    return command


def check_prerequisites(instance: dict[str, Any], platform: dict[str, str]) -> None:
    required_interface_is_up(instance["network"].get("requiredInterface"), platform["ip"])
    executables = [
        platform[key]
        for key in (
            "curl",
            "env",
            "podman",
            "ip",
            "aardvarkDns",
            "useradd",
            "usermod",
            "passwd",
            "runuser",
            "loginctl",
            "systemctl",
        )
    ]
    if instance["gitlab"].get("caCertificate"):
        executables.append(platform["trust"])
    for executable in executables:
        if not Path(executable).is_file():
            raise RunnerError(f"required host executable is missing: {executable}")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise RunnerError("rootless Podman Runner hosts require cgroup v2")
    verify_aardvark(platform)
    run(health_command(instance, platform), capture=True)


def _check_impl(
    instance_name: str,
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    progress: Progress,
) -> None:
    require_root()
    with progress.task("Checking prerequisites"):
        check_prerequisites(instance, platform)
    with progress.external_output():
        print(f"{instance_name}: prerequisites ready")


def check(instance_name: str, instance: dict[str, Any], platform: dict[str, str]) -> None:
    with progress_task("runnerctl check", "Running check") as progress:
        _check_impl(instance_name, instance, platform, progress=progress)


def _reconcile_impl(
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    paths: HostPaths = HostPaths(),
    progress: Progress,
) -> bool:
    require_root()
    with progress.task("Checking prerequisites"):
        check_prerequisites(instance, platform)

    with progress.task("Preparing account, sub-IDs and runtime"):
        with progress.external_output():
            entry = ensure_account(instance, platform)
            account = instance["account"]
            ensure_subordinate_range(paths.subuid, entry.pw_name, account["subUid"])
            ensure_subordinate_range(paths.subgid, entry.pw_name, account["subGid"])
            run([platform["loginctl"], "enable-linger", entry.pw_name])
            run([platform["systemctl"], "start", f"user@{entry.pw_uid}.service"])
            wait_for_path(paths.runtime / str(entry.pw_uid) / "bus")
            verify_rootless_podman(entry, platform)
            config_dir, _, unit_dir = ensure_directories(entry)
    pending = config_dir / ".reconcile.pending"

    def mark_pending():
        atomic_write(pending, "pending\n", mode=0o600, uid=entry.pw_uid, gid=entry.pw_gid)

    with progress.task("Reconciling trust and configuration"):
        with progress.external_output():
            ca_changed = reconcile_ca(instance, entry, config_dir, platform, mark_pending)
            config_path = config_dir / "config.toml"
            metadata = registration_metadata(config_path)
            template_changed = atomic_write(
                config_dir / "registration-template.toml",
                render_registration_template(instance),
                mode=0o600,
                uid=entry.pw_uid,
                gid=entry.pw_gid,
                before_change=mark_pending,
            )
            config_changed = atomic_write(
                config_path,
                render_config(instance, metadata),
                mode=0o600,
                uid=entry.pw_uid,
                gid=entry.pw_gid,
                before_change=mark_pending,
            )
            service_name = instance["runner"]["serviceName"]
            unit_changed = atomic_write(
                unit_dir / f"{service_name}.service",
                render_service(instance),
                mode=0o600,
                uid=entry.pw_uid,
                gid=entry.pw_gid,
                before_change=mark_pending,
            )

    retry_pending = pending.exists()
    with progress.task("Preparing user services"):
        with progress.external_output():
            if unit_changed or retry_pending:
                run_as(
                    entry,
                    [platform["systemctl"], "--user", "daemon-reload"],
                    platform=platform,
                )
            run_as(
                entry,
                [platform["systemctl"], "--user", "enable", "--now", "podman.socket"],
                platform=platform,
            )
    with progress.task("Preparing manager image"):
        image = instance["runner"]["managerImage"]
        image_exists = run_as(
            entry,
            [platform["podman"], "image", "exists", image],
            platform=platform,
            capture=True,
            check=False,
        )
        image_pulled = image_exists.returncode == 1
        if image_pulled:
            mark_pending()
            with progress.external_output():
                run_as(entry, [platform["podman"], "pull", image], platform=platform)
        elif image_exists.returncode != 0:
            raise RunnerError("unable to inspect the Runner manager image")
    service_unit = f"{service_name}.service"
    with progress.task("Converging Runner service"):
        with progress.external_output():
            run_as(
                entry,
                [platform["systemctl"], "--user", "enable", service_unit],
                platform=platform,
            )
            service_active = run_as(
                entry,
                [platform["systemctl"], "--user", "is-active", service_unit],
                platform=platform,
                capture=True,
                check=False,
            )
            manager_drift = (
                service_active.returncode == 0
                and inspect_manager(instance, platform, entry) != "matches-declaration"
            )
            if manager_drift:
                mark_pending()
            if service_active.returncode != 0:
                run_as(
                    entry,
                    [platform["systemctl"], "--user", "start", service_unit],
                    platform=platform,
                )
            elif retry_pending or image_pulled or manager_drift:
                run_as(
                    entry,
                    [platform["systemctl"], "--user", "restart", service_unit],
                    platform=platform,
                )
    remove_managed_file(pending)
    return (
        retry_pending
        or template_changed
        or config_changed
        or unit_changed
        or ca_changed
        or image_pulled
        or manager_drift
        or service_active.returncode != 0
    )


def reconcile(
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    paths: HostPaths = HostPaths(),
    progress: Progress | None = None,
) -> bool:
    with progress_task("runnerctl reconcile", "Reconciling Runner", progress) as current:
        return _reconcile_impl(instance, platform, paths=paths, progress=current)


def _register_impl(
    instance: dict[str, Any], platform: dict[str, str], *, progress: Progress
) -> None:
    require_root()
    token = os.environ.get("GITLAB_RUNNER_TOKEN", "")
    if not (token.startswith("glrt-") or token.startswith("glrtr-")):
        raise RunnerError("GITLAB_RUNNER_TOKEN must contain a Runner authentication token")
    try:
        entry = pwd.getpwnam(instance["account"]["user"])
    except KeyError as error:
        raise RunnerError("reconcile the Runner instance before registration") from error
    config_path = Path(entry.pw_dir) / "gitlab-runner/config/config.toml"
    metadata = registration_metadata(config_path)
    if "token" in metadata:
        if metadata["token"] != token:
            raise RunnerError("the dedicated stack already contains a different registration")
        reconcile(instance, platform, progress=progress)
        verify(instance, platform, progress=progress)
        return

    service_name = instance["runner"]["serviceName"]
    runtime_dir = f"/run/user/{entry.pw_uid}"
    registration_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": entry.pw_dir,
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
        "CI_SERVER_URL": instance["gitlab"]["url"],
        "CI_SERVER_TOKEN": token,
        "REGISTER_NON_INTERACTIVE": "true",
    }
    command = [
        platform["runuser"],
        "--preserve-environment",
        "--user",
        entry.pw_name,
        "--",
        platform["podman"],
        "exec",
        "--env",
        "CI_SERVER_URL",
        "--env",
        "CI_SERVER_TOKEN",
        "--env",
        "REGISTER_NON_INTERACTIVE",
        service_name,
        "gitlab-runner",
        "register",
        "--template-config",
        "/etc/gitlab-runner/registration-template.toml",
    ]
    with progress.external_output():
        result = subprocess.run(
            command,
            env=registration_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
        )
    if result.returncode != 0:
        raise RunnerError("Runner registration failed; output was suppressed to protect the token")
    reconcile(instance, platform, progress=progress)
    verify(instance, platform, progress=progress)


def register(
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    progress: Progress | None = None,
) -> None:
    with progress_task("runnerctl register", "Registering Runner", progress) as current:
        _register_impl(instance, platform, progress=current)


def validate_job_network(
    instance: dict[str, Any],
    platform: dict[str, str],
    entry: pwd.struct_passwd,
) -> None:
    service_name = instance["runner"]["serviceName"]
    network_name = f"runnerctl-verify-{service_name}-{os.getpid()}"
    run_as(
        entry,
        [platform["podman"], "network", "create", network_name],
        platform=platform,
        capture=True,
    )
    try:
        command = [
            platform["podman"],
            "run",
            "--rm",
            "--pull=missing",
            "--network",
            network_name,
        ]
        dns = instance["network"].get("dns")
        if dns:
            command.extend(["--dns", dns])
        ca_certificate = instance["gitlab"].get("caCertificate")
        if ca_certificate:
            manager_certificate = (
                Path(entry.pw_dir)
                / "gitlab-runner/config/certs"
                / f"{gitlab_hostname(instance)}.crt"
            )
            command.extend(["--volume", f"{manager_certificate}:/tmp/runner-ca.crt:ro,Z"])
        command.extend(
            [
                instance["validation"]["image"],
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
            ]
        )
        if ca_certificate:
            command.extend(["--cacert", "/tmp/runner-ca.crt"])
        command.append(instance["gitlab"]["healthUrl"])
        run_as(entry, command, platform=platform, capture=True)
    finally:
        run_as(
            entry,
            [platform["podman"], "network", "rm", "--force", network_name],
            platform=platform,
            capture=True,
            check=False,
        )


def inspect_manager(instance, platform, entry):
    result = run_as(
        entry,
        [
            platform["podman"],
            "inspect",
            "--format",
            '{"running":{{json .State.Running}},"network":{{json .HostConfig.NetworkMode}},'
            '"privileged":{{json .HostConfig.Privileged}},"mounts":{{json .Mounts}},"image":{{json .Image}}}',
            instance["runner"]["serviceName"],
        ],
        platform=platform,
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        return "absent"
    image = run_as(
        entry,
        [
            platform["podman"],
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            instance["runner"]["managerImage"],
        ],
        platform=platform,
        capture=True,
        check=False,
    )
    try:
        matches = image.returncode == 0 and manager_matches(
            instance, entry.pw_uid, json.loads(result.stdout), image.stdout.strip()
        )
    except (ValueError, TypeError):
        matches = False
    return "matches-declaration" if matches else "drifted"


def _verify_impl(instance: dict[str, Any], platform: dict[str, str], *, progress: Progress) -> None:
    require_root()
    with progress.task("Checking runtime and socket"):
        with progress.external_output():
            required_interface_is_up(instance["network"].get("requiredInterface"), platform["ip"])
            entry = pwd.getpwnam(instance["account"]["user"])
            verify_rootless_podman(entry, platform)
            verify_aardvark(platform)
            socket_path = Path(f"/run/user/{entry.pw_uid}/podman/podman.sock")
            if not socket_path.exists() or not stat.S_ISSOCK(socket_path.stat().st_mode):
                raise RunnerError(f"rootless Podman socket is unavailable for {entry.pw_name}")
    service_name = instance["runner"]["serviceName"]
    with progress.task("Checking registration and service"):
        metadata = registration_metadata(Path(entry.pw_dir) / "gitlab-runner/config/config.toml")
        if "token" not in metadata:
            raise RunnerError("the dedicated Runner stack is not registered")
        run_as(
            entry,
            [platform["systemctl"], "--user", "is-active", f"{service_name}.service"],
            platform=platform,
            capture=True,
        )
        if inspect_manager(instance, platform, entry) != "matches-declaration":
            raise RunnerError("Runner manager does not match declared image, mounts or isolation")
    with progress.task("Checking GitLab verification"):
        runner_help = run_as(
            entry,
            [platform["podman"], "exec", service_name, "gitlab-runner", "--help"],
            platform=platform,
            capture=True,
        )
        if re.search(r"(?m)^\s+lint\s+", runner_help.stdout):
            run_as(
                entry,
                [
                    platform["podman"],
                    "exec",
                    service_name,
                    "gitlab-runner",
                    "lint",
                    "--config",
                    "/etc/gitlab-runner/config.toml",
                ],
                platform=platform,
                capture=True,
            )
        run_as(
            entry,
            [platform["podman"], "exec", service_name, "gitlab-runner", "verify"],
            platform=platform,
            capture=True,
        )
    with progress.task("Checking GitLab health"):
        run(health_command(instance, platform), capture=True)
    with progress.task("Checking disposable job network"):
        with progress.external_output():
            validate_job_network(instance, platform, entry)


def subordinate_range_matches(path: Path, user: str, desired: dict[str, int]) -> bool:
    if not path.exists():
        return False
    expected = f"{user}:{desired['start']}:{desired['count']}"
    return [line.strip() for line in path.read_text().splitlines()].count(expected) == 1


def verify(
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    progress: Progress | None = None,
) -> None:
    with progress_task("runnerctl verify", "Verifying Runner", progress) as current:
        _verify_impl(instance, platform, progress=current)


def _status_impl(
    instance_name: str,
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    progress: Progress,
) -> None:
    require_root()
    account_name = instance["account"]["user"]
    try:
        entry = pwd.getpwnam(account_name)
    except KeyError:
        with progress.external_output():
            print(
                f"{instance_name}: account=missing, subids=missing, socket=missing, "
                "service=unavailable, container=absent, registration=absent"
            )
        return
    runtime_dir = f"/run/user/{entry.pw_uid}"
    environment = {
        "PATH": "/usr/bin",
        "HOME": entry.pw_dir,
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
    }
    result = subprocess.run(
        [
            platform["runuser"],
            "--user",
            entry.pw_name,
            "--",
            platform["systemctl"],
            "--user",
            "is-active",
            f"{instance['runner']['serviceName']}.service",
        ],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    state = result.stdout.strip() or "unavailable"
    config_path = Path(entry.pw_dir) / "gitlab-runner/config/config.toml"
    try:
        registered = "present" if "token" in registration_metadata(config_path) else "absent"
    except RunnerError:
        registered = "invalid"
    socket_path = Path(f"/run/user/{entry.pw_uid}/podman/podman.sock")
    socket_state = (
        "present"
        if socket_path.exists() and stat.S_ISSOCK(socket_path.stat().st_mode)
        else "missing"
    )
    account = instance["account"]
    subids = (
        "ok"
        if subordinate_range_matches(Path("/etc/subuid"), entry.pw_name, account["subUid"])
        and subordinate_range_matches(Path("/etc/subgid"), entry.pw_name, account["subGid"])
        else "drifted"
    )
    container = inspect_manager(instance, platform, entry)
    with progress.external_output():
        print(
            f"{instance_name}: account=present, subids={subids}, socket={socket_state}, "
            f"service={state}, container={container}, registration={registered}"
        )


def status(
    instance_name: str,
    instance: dict[str, Any],
    platform: dict[str, str],
    *,
    progress: Progress | None = None,
) -> None:
    with progress_task("runnerctl status", "Inspecting Runner status", progress) as current:
        _status_impl(instance_name, instance, platform, progress=current)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help=argparse.SUPPRESS)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    for command in ("check", "reconcile", "register", "verify", "status"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("instance")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = json.loads(args.config.read_text())
    instances = document["instances"]
    platform = document["platform"]
    validate_instances(instances)
    if args.command == "validate":
        print("GitLab Runner configuration is valid")
        return 0

    instance = select_instance(instances, args.instance)
    if args.command == "check":
        check(args.instance, instance, platform)
    elif args.command == "status":
        status(args.instance, instance, platform)
    else:
        require_root()
        with operation_lock():
            if args.command == "reconcile":
                changed = reconcile(instance, platform)
                print(f"{args.instance}: {'changed' if changed else 'unchanged'}")
            elif args.command == "register":
                register(instance, platform)
            elif args.command == "verify":
                verify(instance, platform)
                print(f"{args.instance}: verified")
    return 0


def main_cli() -> None:
    try:
        sys.exit(main())
    except subprocess.TimeoutExpired:
        print(
            "runnerctl: operation timed out; rerun the selected operation",
            file=sys.stderr,
        )
        sys.exit(1)
    except (RunnerError, KeyError, ValueError, OSError) as error:
        print(f"runnerctl: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main_cli()
