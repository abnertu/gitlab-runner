"""Record approved real read-only commands as a sanitized terminal transcript."""

from __future__ import annotations

import argparse
import errno
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import time
from contextlib import suppress
from pathlib import Path

from redact import Redactor

PROFILE: str = "runner"
MEDIA = Path(__file__).resolve().parent


def collect(master: int, deadline: float) -> tuple[bytes, bool]:
    """Collect bounded PTY output, retaining partial bytes on timeout."""
    output = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return bytes(output), True
        if not select.select([master], [], [], min(remaining, 0.2))[0]:
            continue
        try:
            chunk = os.read(master, 65536)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > 2_000_000:
            raise ValueError("Output exceeded the safe recording limit")
    return bytes(output), False


def stop(process: subprocess.Popen[bytes]) -> None:
    """Stop the entire failed capture process group and reap its parent."""
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def execute(command: list[str], label: str, env: dict[str, str], redactor: Redactor) -> str:
    """Run a real command and sanitize both output streams before logging."""
    label = redactor.clean(label)
    master, slave = pty.openpty()
    termios.tcsetwinsize(slave, (28, 100))
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=slave,
            stderr=slave,
            env=env,
            process_group=0,
        )
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    deadline = time.monotonic() + 180
    finished = False
    try:
        output, timed_out = collect(master, deadline)
        if not timed_out:
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
                finished = True
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        os.close(master)
        if not finished:
            stop(process)
    safe = redactor.clean(output.decode("utf-8", errors="strict"), color=True)
    print(safe, end="", flush=True)
    if timed_out:
        raise SystemExit(f"{label}: timed out; recording rejected")
    if process.returncode:
        raise SystemExit(f"{label}: exit {process.returncode}; recording rejected")
    return safe


def authenticate(file: Path | None) -> None:
    """Pass an optional authorized descriptor directly to native sudo."""
    if file is not None:
        with file.open("rb") as credential:
            result = subprocess.run(
                ["sudo", "-S", "-p", "", "-v"],
                stdin=credential,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
            )
        if result.returncode:
            raise SystemExit("Sudo authentication failed; nothing recorded")
    result = subprocess.run(
        ["sudo", "-n", "true"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    if result.returncode:
        raise SystemExit("Authenticate in this terminal before recording")


def commands(args: argparse.Namespace) -> list[tuple[list[str], str]]:
    """Restrict capture to the reviewed installed CLI or configured controller."""
    program = str(args.command.resolve())
    if PROFILE == "nacre":
        return [
            ([program, action], "nacre " + action) for action in ("--version", "status", "build")
        ]
    instances = args.instance
    if any(not re.fullmatch(r"[a-z][a-z0-9-]{0,17}", name) for name in instances):
        raise SystemExit("Use the actual declared Runner instance names")
    selected = [
        ([program, "--version"], "runnerctl --version"),
        ([program, "validate"], "runnerctl validate"),
    ]
    return selected + [
        (["sudo", "-n", program, "plan", name], "sudo runnerctl plan " + name) for name in instances
    ]


def write_cast(path: Path, results: list[tuple[str, str]]) -> None:
    """Pace real sanitized output in readable pages without inventing results."""
    events: list[list[object]] = []
    clock = 0.0
    for label, output in results:
        if events:
            clock += 3
            events.append([clock, "o", "\x1b[2J\x1b[H"])
        events.append(
            [clock, "o", "\x1b[2mDevelopment CLI | actual machine configuration\x1b[0m\r\n"]
        )
        events.append([clock, "o", "\x1b[38;2;125;170;255m$\x1b[0m " + label + "\r\n"])
        clock += 0.7
        rows = 0
        page: list[str] = []
        for line in output.splitlines():
            height = max(1, (len(re.sub(r"\x1b\[[0-9;]*m", "", line)) + 95) // 96)
            if rows + height > (9 if PROFILE == "nacre" else 23) and page:
                events.append([clock, "o", "\r\n".join(page) + "\r\n"])
                clock += 5
                rows, page = 0, []
            page.append(line)
            rows += height
        if page:
            events.append([clock, "o", "\r\n".join(page) + "\r\n"])
        clock += 0.3
        events.append([clock, "o", "\x1b[38;2;125;170;255m$\x1b[0m "])
    header = {"version": 2, "width": 100, "height": 28, "env": {"TERM": "xterm-256color"}}
    path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in [header, *events]) + "\n"
    )


def main() -> None:
    """Capture only successful real commands and publish a reviewed GIF later."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--command", type=Path, required=PROFILE == "runner", default=shutil.which("nacre")
    )
    if PROFILE == "nacre":
        parser.add_argument("--machine", type=Path, required=True)
    else:
        parser.add_argument("--instance", action="append", required=True)
        parser.add_argument("--sudo-password-file", type=Path)
    args = parser.parse_args()
    expected = "nacre" if PROFILE == "nacre" else "runnerctl"
    if (
        args.command is None
        or args.command.name != expected
        or not os.access(args.command, os.X_OK)
    ):
        parser.error("The actual executable is unavailable")
    if not shutil.which("agg"):
        parser.error("Run the recorder with agg on PATH")
    env = dict(os.environ, TERM="xterm-256color")
    for key in ("NO_COLOR", "CI", "NIX_LOG_FORMAT"):
        env.pop(key, None)
    machine = getattr(args, "machine", None)
    if machine and not (machine / "flake.nix").is_file():
        parser.error("The actual machine flake is unavailable")
    if machine:
        env["NACRE_FLAKE"] = str(machine.resolve())
    redactor = Redactor(str(machine.resolve()) if machine else None)
    if PROFILE == "runner":
        authenticate(args.sudo_password_file)
    with tempfile.TemporaryDirectory(prefix="real-command-demo-") as directory:
        root = Path(directory)
        results: list[tuple[str, str]] = []
        for command, label in commands(args):
            if command[0] == "sudo":
                authenticate(None)
            results.append((redactor.clean(label), execute(command, label, env, redactor)))
        cast, gif = root / "demo.cast", root / "demo.gif"
        write_cast(cast, results)
        subprocess.run(
            [
                "agg",
                "--font-size",
                "22",
                "--theme",
                "nord",
                "--fps-cap",
                "15",
                "--last-frame-duration",
                "5",
                str(cast),
                str(gif),
            ],
            check=True,
            timeout=120,
        )
        shutil.copyfile(gif, MEDIA.parent / "demo.gif")


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        print("Recording failed before publication; raw diagnostics suppressed", file=sys.stderr)
        raise SystemExit(1) from None
