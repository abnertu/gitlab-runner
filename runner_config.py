"""Load Runner instances from per-environment TOML files.

Each instance file is named after the environment it serves: `frontend.toml`
declares the `frontend` instance. A file may name one shared base through
`extends`, resolved relative to itself; bases cannot extend further. Unknown
keys are rejected, so a typo never silently falls back to a default.
"""

from __future__ import annotations

from pathlib import Path
import re
import tomllib
from typing import Any

from runner_model import RunnerError, render_artifacts

PROVIDERS = ("gitlab",)
MANAGER_IMAGE = "docker.io/gitlab/gitlab-runner:v18.10.1"
VALIDATION_IMAGE = "docker.io/curlimages/curl:8.12.1"
SUBORDINATE_ID_COUNT = 65536
INSTANCE_NAME = re.compile(r"[a-z][a-z0-9-]{0,17}")

SCHEMA: dict[str, Any] = {
    "extends": str,
    "provider": str,
    "uid": int,
    "subordinate_id_start": int,
    "gitlab": {"url": str, "health_url": str, "ca_certificate": str},
    "runner": {
        "name": str,
        "cpus": str,
        "memory": str,
        "shm_size_bytes": int,
        "default_job_image": str,
        "allowed_images": list,
        "allowed_services": list,
    },
    "network": {"required_interface": str, "dns": str},
}
REQUIRED = {
    "provider": None,
    "uid": None,
    "subordinate_id_start": None,
    "gitlab": ("url", "health_url"),
    "runner": (
        "name",
        "cpus",
        "memory",
        "shm_size_bytes",
        "default_job_image",
        "allowed_images",
    ),
}

# Absolute host executables and directories for each supported platform.
PLATFORMS: dict[str, dict[str, str]] = {
    "arch": {
        "curl": "/usr/bin/curl",
        "env": "/usr/bin/env",
        "podman": "/usr/bin/podman",
        "ip": "/usr/bin/ip",
        "aardvarkDns": "/usr/lib/podman/aardvark-dns",
        "trust": "/usr/bin/trust",
        "useradd": "/usr/bin/useradd",
        "passwd": "/usr/bin/passwd",
        "usermod": "/usr/bin/usermod",
        "runuser": "/usr/bin/runuser",
        "loginctl": "/usr/bin/loginctl",
        "systemctl": "/usr/bin/systemctl",
        "caAnchorDirectory": "/etc/ca-certificates/trust-source/anchors",
        "containerCertsDirectory": "/etc/containers/certs.d",
    },
}


def detect_platform(os_release: Path = Path("/etc/os-release")) -> str:
    try:
        fields = dict(
            line.split("=", 1) for line in os_release.read_text().splitlines() if "=" in line
        )
    except OSError:
        raise RunnerError("cannot detect the host platform; pass --platform") from None
    platform = fields.get("ID", "").strip('"')
    if platform not in PLATFORMS:
        raise RunnerError(f"unsupported host platform: {platform or 'unknown'}")
    return platform


def platform_paths(name: str) -> dict[str, str]:
    try:
        return PLATFORMS[name]
    except KeyError:
        supported = ", ".join(sorted(PLATFORMS))
        raise RunnerError(f"unsupported platform {name}; supported: {supported}") from None


def _read(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text())
    except OSError as error:
        raise RunnerError(f"cannot read {path}: {error.strerror}") from None
    except tomllib.TOMLDecodeError as error:
        raise RunnerError(f"{path} is not valid TOML: {error}") from None


def _check_schema(document: dict[str, Any], schema: dict[str, Any], context: str) -> None:
    for key, value in document.items():
        if key not in schema:
            raise RunnerError(f"{context} has unknown key: {key}")
        expected = schema[key]
        if isinstance(expected, dict):
            if not isinstance(value, dict):
                raise RunnerError(f"{context}.{key} must be a table")
            _check_schema(value, expected, f"{context}.{key}")
        elif isinstance(value, bool) or not isinstance(value, expected):
            raise RunnerError(f"{context}.{key} must be a {expected.__name__}")
        elif expected is list and not all(isinstance(item, str) for item in value):
            raise RunnerError(f"{context}.{key} must contain only strings")


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def _read_checked(path: Path) -> dict[str, Any]:
    document = _read(path)
    _check_schema(document, SCHEMA, path.name)
    gitlab = document.get("gitlab", {})
    if "ca_certificate" in gitlab:
        # A relative certificate path belongs to the file that declares it.
        gitlab["ca_certificate"] = str(path.parent / gitlab["ca_certificate"])
    return document


def load_document(path: Path) -> dict[str, Any]:
    """Read one instance file with its optional base, schema-checked and merged."""
    document = _read_checked(path)
    base_name = document.pop("extends", None)
    if base_name is None:
        merged = document
    else:
        base_path = path.parent / base_name
        base = _read_checked(base_path)
        if "extends" in base:
            raise RunnerError(f"{base_path.name} is a base and cannot extend another file")
        merged = _merge(base, document)
    for key, fields in REQUIRED.items():
        if key not in merged:
            raise RunnerError(f"{path.name} is missing required key: {key}")
        for field in fields or ():
            if field not in merged[key]:
                raise RunnerError(f"{path.name} is missing required key: {key}.{field}")
    if merged["provider"] not in PROVIDERS:
        raise RunnerError(f"{path.name} uses unsupported provider: {merged['provider']}")
    return merged


def normalize(name: str, document: dict[str, Any]) -> dict[str, Any]:
    """Derive the internal instance model that runnerctl operations consume."""
    if not INSTANCE_NAME.fullmatch(name):
        raise RunnerError(
            f"invalid instance name {name}: use [a-z][a-z0-9-] and at most 18 characters"
        )
    user = f"gitlab-runner-{name}"
    ids = {"start": document["subordinate_id_start"], "count": SUBORDINATE_ID_COUNT}
    gitlab = document["gitlab"]
    runner = document["runner"]
    network = document.get("network", {})
    instance = {
        "account": {
            "user": user,
            "uid": document["uid"],
            "home": f"/home/{user}",
            "subUid": dict(ids),
            "subGid": dict(ids),
        },
        "gitlab": {
            "url": gitlab["url"],
            "healthUrl": gitlab["health_url"],
            "caCertificate": gitlab.get("ca_certificate"),
        },
        "runner": {
            "name": runner["name"],
            "cpus": runner["cpus"],
            "memory": runner["memory"],
            "shmSizeBytes": runner["shm_size_bytes"],
            "defaultJobImage": runner["default_job_image"],
            "allowedImages": runner["allowed_images"],
            "allowedServices": runner.get("allowed_services", []),
            "serviceName": user,
            "managerImage": MANAGER_IMAGE,
            "concurrent": 1,
            "pullPolicy": "if-not-present",
        },
        "network": {
            "requiredInterface": network.get("required_interface"),
            "dns": network.get("dns"),
        },
        "validation": {"image": VALIDATION_IMAGE},
    }
    instance["artifacts"] = render_artifacts(instance)
    return instance


def load_instances(paths: list[Path]) -> dict[str, dict[str, Any]]:
    """Load instance files; each file's stem names its instance."""
    instances: dict[str, dict[str, Any]] = {}
    for path in paths:
        name = path.stem
        if path.suffix != ".toml":
            raise RunnerError(f"{path} must be a .toml instance file")
        if name in instances:
            raise RunnerError(f"instance {name} is declared by more than one file")
        instances[name] = normalize(name, load_document(path))
    return instances
