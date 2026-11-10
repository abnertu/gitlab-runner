"""Redact personal identifiers before terminal data reaches logs or artifacts."""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
import socket
import sys
from collections.abc import Callable
from pathlib import Path

ANSI = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]", re.DOTALL)
IP = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:.]+"
)
EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
URL = re.compile(r"https?://[^\s\"'<>]+")
SECRET = re.compile(
    r"(?i)\b(password|token|secret|authorization|access[-_]token)\s*[:=]\s*[^\r\n]+"
)


SGR = re.compile(r"\x1b\[([0-9;]*)m")
SAFE_STYLES = {0, 1, 2, 3, 4, 22, 23, 24, 39, *range(30, 38), *range(90, 98)}


class StyledText:
    """Redact whole visible text before restoring vetted native SGR spans."""

    def __init__(self, raw: str) -> None:
        """Strip controls while tracking the style of each visible character."""
        parts: list[str] = []
        self.styles: list[str] = []
        position, active = 0, ""
        for match in ANSI.finditer(raw):
            part = raw[position : match.start()]
            parts.append(part)
            self.styles.extend([active] * len(part))
            sgr = SGR.fullmatch(match.group())
            if sgr:
                codes = [int(code or "0") for code in sgr[1].split(";")]
                if all(code in SAFE_STYLES for code in codes):
                    if 0 in codes:
                        active = ""
                    if any(codes):
                        active += match.group()
                    if len(active) > 256:
                        raise ValueError("Excessive terminal style sequence")
            position = match.end()
        parts.append(raw[position:])
        self.styles.extend([active] * len(raw[position:]))
        self.text = "".join(parts)

    def replace(
        self,
        pattern: str | re.Pattern[str],
        replacement: str | Callable[[re.Match[str]], str],
        flags: int = 0,
    ) -> None:
        """Replace complete matches, assigning replacements only their old style."""
        parts: list[str] = []
        styles: list[str] = []
        position = 0
        for match in re.compile(pattern, flags).finditer(self.text):
            parts.append(self.text[position : match.start()])
            styles.extend(self.styles[position : match.start()])
            value = replacement(match) if callable(replacement) else match.expand(replacement)
            parts.append(value)
            style = self.styles[match.start()] if match.start() < len(self.styles) else ""
            styles.extend([style] * len(value))
            position = match.end()
        parts.append(self.text[position:])
        styles.extend(self.styles[position:])
        self.text, self.styles = "".join(parts), styles

    def render(self, *, color: bool) -> str:
        """Emit only sanitized characters and vetted style transitions."""
        if not color:
            return self.text
        parts: list[str] = []
        active = ""
        for character, style in zip(self.text, self.styles, strict=True):
            if style != active:
                parts.append("\x1b[0m" + style)
                active = style
            parts.append(character)
        if active:
            parts.append("\x1b[0m")
        return "".join(parts)


def private_ip(match: re.Match[str]) -> str:
    """Mask private, loopback and link-local addresses."""
    try:
        address = ipaddress.ip_address(match.group())
    except ValueError:
        return match.group()
    return match.group() if address.is_global else "[private-ip]"


class Redactor:
    """Keep runtime identifier values out of reusable recording sources."""

    def __init__(self, machine: str | None = None) -> None:
        """Gather identity metadata without reading application preferences."""
        values = {
            str(Path.home()): "~",
            getpass.getuser(): "[user]",
            socket.gethostname(): "[host]",
        }
        if machine:
            values[machine] = "[machine]"
        self.values = sorted(values.items(), key=lambda pair: -len(pair[0]))

    def clean(self, text: str, *, color: bool = False) -> str:
        """Reject unsupported control sequences instead of leaking raw output."""
        if len(text) > 2_000_000:
            raise ValueError("Output exceeded the safe recording limit")
        styled = StyledText(text)
        text = styled.text
        if "\x1b" in text or any(
            chr(n) in text for n in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))
        ):
            raise ValueError("Unsupported terminal control sequence")
        if any(
            (ord(char) < 32 and char not in "\n\r\t") or 0x7F <= ord(char) < 0xA0 for char in text
        ):
            raise ValueError("Unsupported terminal control character")
        styled.replace(r"\r\n?", "\n")
        styled.replace(URL, "[endpoint]")
        styled.replace(SECRET, r"\1=[redacted]")
        styled.replace(EMAIL, "[email]")
        styled.replace(IP, private_ip)
        for value, replacement in self.values:
            if value:
                styled.replace(re.escape(value), replacement, re.IGNORECASE)
        styled.replace(r"(?im)(\bhostname\s+)[^\n]+", r"\1[host]")
        styled.replace(r"(?i)\b[\w.-]+\.(?:local|lan|internal|home)\b", "[host]")
        styled.replace(r"(?<=certs\.d/)[^/\s]+", "[endpoint]")
        styled.replace(r"(?i)(already owned by )\S+", r"\1[account]")
        styled.replace(r"/home/(?!gitlab-runner-[a-z0-9-]+(?:/|\s|$))[^/\s]+", "/home/[user]")
        styled.replace(r"(?<=/)[^/\s]+\.crt\b", "[certificate]")
        return styled.render(color=color)


def main() -> None:
    """Sanitize complete input before emitting any byte."""
    try:
        data = sys.stdin.buffer.read(2_000_001).decode("utf-8", errors="strict")
        sys.stdout.write(
            Redactor(os.environ.get("NACRE_FLAKE")).clean(data, color="--color" in sys.argv[1:])
        )
    except (UnicodeError, ValueError):
        raise SystemExit("Unsafe terminal input; nothing emitted") from None


if __name__ == "__main__":
    main()
