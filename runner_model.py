"""Pure Runner validation and rendering; no host operations."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from nix_adapter.exceptions import Conflict
from nix_adapter.system import ranges_overlap

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


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def toml_array(values: list[str]) -> str:
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def gitlab_hostname(instance: dict[str, Any]) -> str:
    hostname = urlparse(str(instance["gitlab"]["url"])).hostname
    if hostname is None:
        raise RunnerError("GitLab URL does not contain a hostname")
    return hostname


def validate_instances(instances: dict[str, Any]) -> None:
    users: set[str] = set()
    service_names: set[str] = set()
    uids: set[int] = set()
    for instance_name, instance in instances.items():
        account = instance["account"]
        gitlab = instance["gitlab"]
        runner = instance["runner"]
        network = instance["network"]

        if not re.fullmatch(r"[a-z][a-z0-9-]*", instance_name):
            raise RunnerError(f"invalid instance name: {instance_name}")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", account["user"]):
            raise RunnerError(f"invalid account name for {instance_name}")
        if account["user"] == "root" or len(account["user"]) > 32:
            raise RunnerError(f"unsafe account name for {instance_name}")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]+", runner["serviceName"]):
            raise RunnerError(f"invalid service name for {instance_name}")
        if account["user"] in users or runner["serviceName"] in service_names:
            raise RunnerError("Runner account and service names must be unique")
        if account["uid"] in uids:
            raise RunnerError("Runner account UIDs must be unique")
        users.add(account["user"])
        service_names.add(runner["serviceName"])
        uids.add(account["uid"])

        if not runner["name"]:
            raise RunnerError(f"{instance_name} runner name must not be empty")
        if account["uid"] <= 0:
            raise RunnerError(f"{instance_name} uid must be a positive integer")
        if account["home"] != f"/home/{account['user']}":
            raise RunnerError(f"{instance_name} must use its dedicated /home directory")
        gitlab_url = urlparse(str(gitlab["url"]))
        health_url = urlparse(str(gitlab["healthUrl"]))
        if (
            gitlab_url.scheme != "https"
            or not gitlab_url.hostname
            or health_url.scheme != "https"
            or health_url.hostname != gitlab_url.hostname
        ):
            raise RunnerError(f"{instance_name} GitLab URLs must use the same HTTPS hostname")
        for range_name in ("subUid", "subGid"):
            id_range = account[range_name]
            if id_range["start"] <= 0 or id_range["count"] < 65536:
                raise RunnerError(f"{instance_name} {range_name} must contain at least 65536 IDs")
            if id_range["start"] + id_range["count"] - 1 > 4_294_967_294:
                raise RunnerError(f"{instance_name} has an invalid {range_name} range")
        if account["subUid"] != account["subGid"]:
            raise RunnerError(f"{instance_name} subordinate UID and GID ranges must match")
        for image_name in ("managerImage", "defaultJobImage"):
            image = runner[image_name]
            if not FIXED_IMAGE_PATTERN.fullmatch(image) or image.endswith(":latest"):
                raise RunnerError(f"{instance_name} {image_name} must be qualified and pinned")
        if not runner["allowedImages"] or not any(
            fnmatch.fnmatchcase(runner["defaultJobImage"], pattern)
            for pattern in runner["allowedImages"]
        ):
            raise RunnerError(f"{instance_name} defaultJobImage must match allowedImages")
        validation_image = instance["validation"]["image"]
        if not FIXED_IMAGE_PATTERN.fullmatch(validation_image) or validation_image.endswith(
            ":latest"
        ):
            raise RunnerError(f"{instance_name} validation image must be qualified and pinned")
        for pattern in [*runner["allowedImages"], *runner["allowedServices"]]:
            if not IMAGE_PATTERN.fullmatch(pattern) or pattern.endswith(":latest"):
                raise RunnerError(f"{instance_name} has an invalid image allowlist pattern")
        if runner["concurrent"] != 1:
            raise RunnerError(f"{instance_name} must remain a dedicated concurrent=1 stack")
        try:
            cpus = Decimal(runner["cpus"])
        except InvalidOperation as error:
            raise RunnerError(f"{instance_name} cpus must be positive") from error
        if not cpus.is_finite() or cpus <= 0:
            raise RunnerError(f"{instance_name} cpus must be positive")
        if not MEMORY_PATTERN.fullmatch(runner["memory"]):
            raise RunnerError(f"{instance_name} memory must be a positive size")
        if runner["shmSizeBytes"] <= 0:
            raise RunnerError(f"{instance_name} shmSizeBytes must be positive")
        required_interface = network.get("requiredInterface")
        if required_interface is not None and not re.fullmatch(
            r"[A-Za-z0-9_.:-]+", required_interface
        ):
            raise RunnerError(f"{instance_name} has an invalid requiredInterface")
        dns = network.get("dns")
        if dns is not None:
            try:
                ipaddress.ip_address(dns)
            except ValueError as error:
                raise RunnerError(f"{instance_name} dns must be an IP address") from error
        ca_certificate = gitlab.get("caCertificate")
        if ca_certificate is not None:
            if Path(ca_certificate).suffix.lower() not in {".crt", ".pem"}:
                raise RunnerError(f"{instance_name} CA certificate must use .crt or .pem")
            if not Path(ca_certificate).is_file():
                raise RunnerError(f"{instance_name} CA certificate is missing: {ca_certificate}")

    names = sorted(instances)
    for index, left_name in enumerate(names):
        for right_name in names[index + 1 :]:
            left = instances[left_name]["account"]
            right = instances[right_name]["account"]
            for range_name in ("subUid", "subGid"):
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
    return instance["artifacts"]["registrationTemplate"]


def render_config(instance: dict[str, Any], metadata: dict[str, str]) -> str:
    policy = instance["artifacts"]["configPolicy"]
    config = policy["configPrefix"]
    if "token" not in metadata:
        return config
    registration = policy["registrationPrefix"]
    fields: list[str] = []
    if "id" in metadata:
        fields.append(f"  id = {metadata['id']}")
    fields.append(f"  token = {toml_string(metadata['token'])}")
    for field in ("token_obtained_at", "token_expires_at"):
        if field in metadata:
            fields.append(f"  {field} = {metadata[field]}")
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
