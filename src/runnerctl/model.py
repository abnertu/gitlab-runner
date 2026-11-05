"""Pure Runner validation and rendering; no host operations."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from nix_adapter import Conflict, ranges_overlap

RunnerError = Conflict


FIXED_IMAGE_PATTERN = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+"
    r"(?:@sha256:[a-f0-9]{64}|:[A-Za-z0-9._-]+)$"
)
IMAGE_PATTERN = re.compile(
    r"^[a-z0-9.*?-]+(?::[0-9*]+)?/[A-Za-z0-9._/*?-]+"
    r"(?:@sha256:[a-f0-9*?]{1,64}|:[A-Za-z0-9._*?-]+)$"
)
MEMORY_PATTERN = re.compile(r"^[1-9][0-9]*(?:[kKmMgGtT](?:[bB])?)?$")
LATEST_TAG = ":latest"
# An instance name of at most 18 characters keeps the account name
# gitlab-runner-<name> within the 32-character limit.
INSTANCE_NAME = re.compile(r"[a-z][a-z0-9-]{0,17}")
ACCOUNT_NAME = re.compile(r"[a-z_][a-z0-9_-]*")
SERVICE_NAME = re.compile(r"[A-Za-z0-9_.@-]+")
INTERFACE_NAME = re.compile(r"[A-Za-z0-9_.:-]+")
MAX_ACCOUNT_NAME = 32
MIN_SUBORDINATE_IDS = 65536
MAX_SUBORDINATE_ID = 4_294_967_294
SUBORDINATE_RANGES = ("subUid", "subGid")
CA_SUFFIXES = {".crt", ".pem"}
REGISTRATION_TIMESTAMPS = ("token_obtained_at", "token_expires_at")


def toml_string(value: str) -> str:
    """`value` as a TOML basic string."""
    return json.dumps(value, ensure_ascii=False)


def toml_array(values: list[str]) -> str:
    """`values` as a compact TOML array of strings."""
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def gitlab_hostname(instance: dict[str, Any]) -> str:
    """The hostname of the instance's GitLab URL; raise `RunnerError` if absent."""
    hostname = urlparse(str(instance["gitlab"]["url"])).hostname
    if hostname is None:
        raise RunnerError("GitLab URL does not contain a hostname")
    return hostname


@dataclass
class _Claims:
    """Account names, service names and UIDs already taken by earlier instances."""

    users: set[str] = field(default_factory=set[str])
    services: set[str] = field(default_factory=set[str])
    uids: set[int] = field(default_factory=set[int])


def validate_instances(instances: dict[str, Any]) -> None:
    """Check every instance declaration and their combination.

    Raise `RunnerError` on the first invalid field, on a name, service or UID
    that two instances share, or on overlapping subordinate ID ranges.
    """
    claims = _Claims()
    for name, instance in instances.items():
        _check_identity(name, instance, claims)
        _check_account(name, instance)
        _check_gitlab_urls(name, instance["gitlab"])
        _check_subordinate_ranges(name, instance["account"])
        _check_images(name, instance)
        _check_resources(name, instance["runner"])
        _check_network(name, instance["network"])
        _check_ca_certificate(name, instance["gitlab"])
    _check_disjoint_ranges(instances)


def _check_identity(name: str, instance: dict[str, Any], claims: _Claims) -> None:
    user = instance["account"]["user"]
    service = instance["runner"]["serviceName"]
    uid = instance["account"]["uid"]
    if not INSTANCE_NAME.fullmatch(name):
        raise RunnerError(f"invalid instance name: {name}")
    if not ACCOUNT_NAME.fullmatch(user):
        raise RunnerError(f"invalid account name for {name}")
    if user == "root" or len(user) > MAX_ACCOUNT_NAME:
        raise RunnerError(f"unsafe account name for {name}")
    if not SERVICE_NAME.fullmatch(service):
        raise RunnerError(f"invalid service name for {name}")
    if user in claims.users or service in claims.services:
        raise RunnerError("Runner account and service names must be unique")
    if uid in claims.uids:
        raise RunnerError("Runner account UIDs must be unique")
    claims.users.add(user)
    claims.services.add(service)
    claims.uids.add(uid)


def _check_account(name: str, instance: dict[str, Any]) -> None:
    account = instance["account"]
    if not instance["runner"]["name"]:
        raise RunnerError(f"{name} runner name must not be empty")
    if account["uid"] <= 0:
        raise RunnerError(f"{name} uid must be a positive integer")
    if account["home"] != f"/home/{account['user']}":
        raise RunnerError(f"{name} must use its dedicated /home directory")


def _check_gitlab_urls(name: str, gitlab: dict[str, Any]) -> None:
    coordinator = urlparse(str(gitlab["url"]))
    health = urlparse(str(gitlab["healthUrl"]))
    if (
        coordinator.scheme != "https"
        or not coordinator.hostname
        or health.scheme != "https"
        or health.hostname != coordinator.hostname
    ):
        raise RunnerError(f"{name} GitLab URLs must use the same HTTPS hostname")


def _check_subordinate_ranges(name: str, account: dict[str, Any]) -> None:
    for range_name in SUBORDINATE_RANGES:
        id_range = account[range_name]
        if id_range["start"] <= 0 or id_range["count"] < MIN_SUBORDINATE_IDS:
            raise RunnerError(
                f"{name} {range_name} must contain at least {MIN_SUBORDINATE_IDS} IDs"
            )
        if id_range["start"] + id_range["count"] - 1 > MAX_SUBORDINATE_ID:
            raise RunnerError(f"{name} has an invalid {range_name} range")
    if account["subUid"] != account["subGid"]:
        raise RunnerError(f"{name} subordinate UID and GID ranges must match")


def _pinned(image: str) -> bool:
    return bool(FIXED_IMAGE_PATTERN.fullmatch(image)) and not image.endswith(LATEST_TAG)


def _check_images(name: str, instance: dict[str, Any]) -> None:
    runner = instance["runner"]
    for image_name in ("managerImage", "defaultJobImage"):
        if not _pinned(runner[image_name]):
            raise RunnerError(f"{name} {image_name} must be qualified and pinned")
    allowed = runner["allowedImages"]
    if not allowed or not any(
        fnmatch.fnmatchcase(runner["defaultJobImage"], pattern) for pattern in allowed
    ):
        raise RunnerError(f"{name} defaultJobImage must match allowedImages")
    if not _pinned(instance["validation"]["image"]):
        raise RunnerError(f"{name} validation image must be qualified and pinned")
    for pattern in [*allowed, *runner["allowedServices"]]:
        if not IMAGE_PATTERN.fullmatch(pattern) or pattern.endswith(LATEST_TAG):
            raise RunnerError(f"{name} has an invalid image allowlist pattern")


def _check_resources(name: str, runner: dict[str, Any]) -> None:
    if runner["concurrent"] != 1:
        raise RunnerError(f"{name} must remain a dedicated concurrent=1 stack")
    try:
        cpus = Decimal(runner["cpus"])
    except InvalidOperation as error:
        raise RunnerError(f"{name} cpus must be positive") from error
    if not cpus.is_finite() or cpus <= 0:
        raise RunnerError(f"{name} cpus must be positive")
    if not MEMORY_PATTERN.fullmatch(runner["memory"]):
        raise RunnerError(f"{name} memory must be a positive size")
    if runner["shmSizeBytes"] <= 0:
        raise RunnerError(f"{name} shmSizeBytes must be positive")


def _check_network(name: str, network: dict[str, Any]) -> None:
    interface = network.get("requiredInterface")
    if interface is not None and not INTERFACE_NAME.fullmatch(interface):
        raise RunnerError(f"{name} has an invalid requiredInterface")
    dns = network.get("dns")
    if dns is not None:
        try:
            ipaddress.ip_address(dns)
        except ValueError as error:
            raise RunnerError(f"{name} dns must be an IP address") from error


def _check_ca_certificate(name: str, gitlab: dict[str, Any]) -> None:
    certificate = gitlab.get("caCertificate")
    if certificate is None:
        return
    if Path(certificate).suffix.lower() not in CA_SUFFIXES:
        raise RunnerError(f"{name} CA certificate must use .crt or .pem")
    if not Path(certificate).is_file():
        raise RunnerError(f"{name} CA certificate is missing: {certificate}")


def _check_disjoint_ranges(instances: dict[str, Any]) -> None:
    names = sorted(instances)
    for index, left_name in enumerate(names):
        for right_name in names[index + 1 :]:
            left = instances[left_name]["account"]
            right = instances[right_name]["account"]
            for range_name in SUBORDINATE_RANGES:
                if ranges_overlap(left[range_name], right[range_name]):
                    raise RunnerError(
                        f"{left_name} and {right_name} have overlapping {range_name} ranges"
                    )


def render_artifacts(instance: dict[str, Any]) -> dict[str, Any]:
    """Public, platform-independent Runner configuration; never contains tokens."""
    gitlab = instance["gitlab"]
    runner = instance["runner"]
    dns = instance["network"]["dns"]
    template = [
        "[[runners]]",
        f"  name = {toml_string(runner['name'])}",
        '  executor = "docker"',
        '  environment = ["FF_NETWORK_PER_BUILD=1"]',
        "",
        "  [runners.docker]",
        '    host = "unix:///run/podman/podman.sock"',
        f"    image = {toml_string(runner['defaultJobImage'])}",
        "    privileged = false",
        f"    cpus = {toml_string(runner['cpus'])}",
        f"    memory = {toml_string(runner['memory'])}",
        f"    shm_size = {runner['shmSizeBytes']}",
        f"    pull_policy = {toml_string(runner['pullPolicy'])}",
        '    volumes = ["/cache"]',
        f"    allowed_images = {toml_array(runner['allowedImages'])}",
        f"    allowed_services = {toml_array(runner['allowedServices'])}",
    ]
    if dns is not None:
        template.append(f"    dns = [{toml_string(dns)}]")
    hostname = re.match(r"https://([^/:]+)", gitlab["url"])
    ca_line = ""
    if gitlab["caCertificate"] is not None and hostname is not None:
        certificate = f"/etc/gitlab-runner/certs/{hostname.group(1)}.crt"
        ca_line = f"  tls-ca-file = {toml_string(certificate)}\n"
    return {
        "registrationTemplate": "\n".join(template) + "\n",
        "configPolicy": {
            "configPrefix": f"concurrent = {runner['concurrent']}\ncheck_interval = 3\n"
            "shutdown_timeout = 30\n",
            "registrationPrefix": "\n".join(
                [
                    "[[runners]]",
                    f"  name = {toml_string(runner['name'])}",
                    f"  url = {toml_string(gitlab['url'])}",
                    '  executor = "docker"',
                    "@REGISTRATION_METADATA@",
                ]
            )
            + "\n",
            "caLine": ca_line,
        },
    }


def render_registration_template(instance: dict[str, Any]) -> str:
    """The registration template that `gitlab-runner register` reads."""
    return instance["artifacts"]["registrationTemplate"]


def render_config(instance: dict[str, Any], metadata: dict[str, str]) -> str:
    """The manager config, with the existing registration appended when known."""
    policy = instance["artifacts"]["configPolicy"]
    config = policy["configPrefix"]
    if "token" not in metadata:
        return config
    registration = policy["registrationPrefix"]
    fields: list[str] = []
    if "id" in metadata:
        fields.append(f"  id = {metadata['id']}")
    fields.append(f"  token = {toml_string(metadata['token'])}")
    for key in REGISTRATION_TIMESTAMPS:
        if key in metadata:
            fields.append(f"  {key} = {metadata[key]}")
    registration = registration.replace("@REGISTRATION_METADATA@", "\n".join(fields), 1)
    return (
        config
        + "\n"
        + registration
        + policy["caLine"]
        + "\n"
        + "\n".join(render_registration_template(instance).splitlines()[3:])
        + "\n"
    )


def render_service(instance: dict[str, Any], platform: dict[str, str]) -> str:
    """The manager's user unit; host executable paths come from the platform."""
    account = instance["account"]
    runner = instance["runner"]
    dns = instance["network"]["dns"]
    podman = platform["podman"]
    service = runner["serviceName"]
    runtime = f"/run/user/{account['uid']}"
    root = f"{account['home']}/gitlab-runner"
    lines = [
        "[Unit]",
        f"Description=GitLab Runner manager for {service}",
        "Wants=network-online.target",
        "After=network-online.target podman.socket",
        "Requires=podman.socket",
        "",
        "[Service]",
        "Type=simple",
        f"Environment=XDG_RUNTIME_DIR={runtime}",
        f"Environment=DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus",
        f"ExecStartPre=-{podman} rm --force {service}",
        f"ExecStart={podman} run \\",
        "  --rm \\",
        f"  --name {service} \\",
        "  --network host \\",
        "  --image-volume=ignore \\",
        "  --security-opt label=disable \\",
        "  --stop-signal SIGQUIT \\",
        f"  --volume {root}/config:/etc/gitlab-runner:rw \\",
        f"  --volume {root}/cache:/cache:rw \\",
        f"  --volume {runtime}/podman/podman.sock:/run/podman/podman.sock:rw \\",
        "  --env DOCKER_HOST=unix:///run/podman/podman.sock \\",
    ]
    if dns is not None:
        lines.append(f"  --dns {dns} \\")
    lines += [
        f"  {runner['managerImage']} \\",
        "  run \\",
        "  --user=gitlab-runner \\",
        "  --working-directory=/home/gitlab-runner",
        f"ExecStop=-{podman} stop --time 30 {service}",
        f"ExecStopPost=-{podman} rm --force {service}",
        "Restart=always",
        "RestartSec=5",
        "TimeoutStartSec=120",
        "TimeoutStopSec=45",
        "Delegate=yes",
        "",
        "[Install]",
        "WantedBy=default.target",
    ]
    return "\n".join(lines) + "\n"


def manager_matches(instance: dict[str, Any], uid: int, state: object, image_id: object) -> bool:
    """Evaluate only declared isolation facts; never return raw inspect data."""
    if not isinstance(state, dict) or not isinstance(image_id, str) or not image_id:
        return False
    state = cast("dict[str, Any]", state)
    expected = {
        "/etc/gitlab-runner": f"{instance['account']['home']}/gitlab-runner/config",
        "/cache": f"{instance['account']['home']}/gitlab-runner/cache",
        "/run/podman/podman.sock": f"/run/user/{uid}/podman/podman.sock",
    }
    mounts: object = state.get("mounts")
    if not isinstance(mounts, list) or len(cast("list[object]", mounts)) != len(expected):
        return False
    seen: set[str] = set()
    for item in cast("list[object]", mounts):
        if not isinstance(item, dict):
            return False
        mount = cast("dict[str, Any]", item)
        destination = mount.get("Destination")
        if (
            not isinstance(destination, str)
            or destination in seen
            or destination not in expected
            or mount.get("Source") != expected[destination]
            or mount.get("Type") != "bind"
            or mount.get("RW") is not True
        ):
            return False
        seen.add(destination)
    return (
        state.get("running") is True
        and state.get("network") == "host"
        and state.get("privileged") is False
        and state.get("image") == image_id
    )
