"""Command line of runnerctl: parse arguments and dispatch one operation."""

from __future__ import annotations

import argparse
import importlib.metadata
import subprocess
import sys
from pathlib import Path

from . import diagnostics, operations
from .config import detect_platform, load_instances, platform_paths
from .model import RunnerError, validate_instances

PACKAGE = "gitlab-runnerctl"
DESCRIPTION = "Converge dedicated rootless Podman GitLab Runner instances."


class VersionAction(argparse.Action):
    """Print the installed package version and exit.

    The version is looked up only when the option is given, so a source
    checkout without package metadata still parses every other option.
    """

    def __init__(self, option_strings: list[str], dest: str, **_: object) -> None:
        super().__init__(option_strings, dest, nargs=0, help="show the version and exit")

    def __call__(self, parser: argparse.ArgumentParser, *_: object) -> None:
        """Print `runnerctl <version>` and exit."""
        print(f"runnerctl {importlib.metadata.version(PACKAGE)}")
        parser.exit()


def parse_args() -> argparse.Namespace:
    """Parse the command line; argparse exits on invalid arguments."""
    parser = argparse.ArgumentParser(prog="runnerctl", description=DESCRIPTION)
    parser.add_argument("--version", action=VersionAction)
    parser.add_argument(
        "--verbose", action="store_true", help="show public native command diagnostics"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        action="append",
        required=True,
        metavar="FILE",
        help="instance file named after its environment, e.g. frontend.toml; repeat per instance",
    )
    parser.add_argument(
        "--platform",
        help="host platform for executable paths; detected from /etc/os-release by default",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    for command in (
        "check",
        "preflight",
        "plan",
        "reconcile",
        "purge",
        "register",
        "verify",
        "status",
    ):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("instance")
        if command == "plan":
            command_parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Run the selected command and return its exit status."""
    args = parse_args()
    with diagnostics.configured(verbose=args.verbose):
        return _dispatch(args)


def _dispatch(args: argparse.Namespace) -> int:
    # Every file loads, even for one instance: IDs and names must not collide.
    instances = load_instances(args.config)
    validate_instances(instances)
    if args.command == "validate":
        print("GitLab Runner configuration is valid")
        return 0

    instance = operations.select_instance(instances, args.instance)
    platform = platform_paths(args.platform or detect_platform())
    if args.command == "check":
        operations.check(args.instance, instance, platform)
    elif args.command == "preflight":
        operations.preflight(args.instance, instance, platform)
    elif args.command == "plan":
        operations.plan(args.instance, instance, platform, as_json=args.json)
    elif args.command == "status":
        operations.status(args.instance, instance, platform)
    else:
        operations.require_root()
        with operations.operation_lock():
            if args.command == "reconcile":
                changed = operations.reconcile(instance, platform)
                print(f"{args.instance}: {'changed' if changed else 'unchanged'}")
            elif args.command == "purge":
                changed = operations.purge(instance, platform)
                print(f"{args.instance}: {'changed' if changed else 'unchanged'}")
            elif args.command == "register":
                operations.register(instance, platform)
            elif args.command == "verify":
                operations.verify(instance, platform)
                print(f"{args.instance}: verified")
    return 0


def main_cli() -> None:
    """Console entry point: report `RunnerError`, timeouts and I/O errors briefly."""
    try:
        sys.exit(main())
    except subprocess.TimeoutExpired:
        print(
            "runnerctl: operation timed out; rerun the selected operation",
            file=sys.stderr,
        )
        sys.exit(1)
    except (RunnerError, KeyError, ValueError, OSError, ImportError) as error:
        print(f"runnerctl: {diagnostics.redacted(str(error))}", file=sys.stderr)
        sys.exit(1)
