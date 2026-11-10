"""Scoped, redacted reporting for explicitly public native commands."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar

_VERBOSE = ContextVar("runnerctl_verbose", default=False)
_GITLAB_TOKEN = re.compile(r"glrtr?-[A-Za-z0-9_-]+")
_URI_CREDENTIALS = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@")
_PROXY_KEYS = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def color_enabled() -> bool:
    """Use colors only for an interactive stdout that permits them."""
    return (
        sys.stdout.isatty()
        and os.environ.get("TERM", "dumb") != "dumb"
        and "NO_COLOR" not in os.environ
        and not os.environ.get("CI")
    )


def styled(text: str, code: str) -> str:
    """Emphasize human output without adding escapes to redirected output."""
    return f"\033[{code}m{text}\033[0m" if color_enabled() else text


@contextmanager
def configured(*, verbose: bool) -> Generator[None]:
    """Set verbosity for one CLI invocation, restoring the previous setting."""
    previous = _VERBOSE.set(verbose)
    try:
        yield
    finally:
        _VERBOSE.reset(previous)


def verbose() -> bool:
    """Whether this invocation requests public native diagnostics."""
    return _VERBOSE.get()


def redacted(value: str | bytes | None) -> str:
    """Remove authentication tokens, proxy values, and URI credentials."""
    text = value.decode(errors="replace") if isinstance(value, bytes) else value or ""
    tokens = {
        os.environ.get(key, "") for key in ("GITLAB_RUNNER_TOKEN", "CI_SERVER_TOKEN", *_PROXY_KEYS)
    }
    for token in sorted(filter(None, tokens), key=len, reverse=True):
        text = text.replace(token, "<redacted>")
    return _URI_CREDENTIALS.sub(r"\1<redacted>@", _GITLAB_TOKEN.sub("<redacted>", text))


def streams(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    """Format both public command streams, retaining empty-stream labels."""
    return f"stdout:\n{redacted(stdout) or '<empty>'}\nstderr:\n{redacted(stderr) or '<empty>'}"


def emit(text: str) -> None:
    """Write redacted diagnostics to stderr, preserving stdout protocols."""
    print(redacted(text), file=sys.stderr)
