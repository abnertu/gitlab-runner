# pyright: standard
"""Exercise diagnostic policy through real CLI and synthetic native commands."""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import test_retirement as retirement_support

from runnerctl import cli, diagnostics, operations
from runnerctl.config import PLATFORMS

FIXTURE = Path(__file__).parent / "fixtures/frontend.toml"


class DiagnosticCliTests(unittest.TestCase):
    def setUp(self):
        self.platform = PLATFORMS["arch"]
        self.native = mock.Mock(side_effect=AssertionError("unexpected native command"))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(operations.subprocess, "run", self.native))
        self.stack.enter_context(mock.patch.object(operations, "require_root"))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))

    def invoke(self, command="check", *, verbose=False, extra=()):
        arguments = ["runnerctl", "--platform", "arch", "-c", str(FIXTURE)]
        if verbose:
            arguments.append("--verbose")
        arguments += [command, "frontend", *extra]
        stdout, stderr = StringIO(), StringIO()
        with (
            mock.patch.object(sys, "argv", arguments),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as exited,
        ):
            cli.main_cli()
        return exited.exception.code, stdout.getvalue(), stderr.getvalue()

    def prerequisites(self, failure=None, code=0):
        self.stack.enter_context(mock.patch.object(Path, "is_file", return_value=True))

        def native(argv, **kwargs):
            self.assertTrue(kwargs["capture_output"])
            if argv[0] == self.platform["ip"]:
                return subprocess.CompletedProcess(argv, 0, '[{"flags":["UP"]}]', "")
            if argv[0] == self.platform["aardvarkDns"]:
                return subprocess.CompletedProcess(argv, 0, "aardvark-dns 1.11.0", "")
            if argv[0] != self.platform["curl"]:
                self.fail("unexpected native command")
            if failure is not None:
                raise failure
            return subprocess.CompletedProcess(argv, code, "public output", "public error")

        self.native.side_effect = native

    def test_health_response_body_never_reaches_verbose_diagnostics(self):
        self.prerequisites()
        original = self.native.side_effect

        def native(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[0] == self.platform["curl"]:
                # Emulate curl's output-file behavior without network access.
                output = argv.index("--output") + 1 if "--output" in argv else None
                result.stdout = (
                    "" if output and argv[output] == "/dev/null" else "private-response-body"
                )
            return result

        self.native.side_effect = native
        code, stdout, stderr = self.invoke(verbose=True)
        self.assertEqual(code, 0)
        self.assertNotIn("private-response-body", stdout + stderr)

    def test_checked_failure_retains_both_redacted_streams_in_both_modes(self):
        self.prerequisites(code=7)
        token = "fixture-environment-authentication"
        for verbose in (False, True):
            with (
                self.subTest(verbose=verbose),
                mock.patch.dict(os.environ, {"GITLAB_RUNNER_TOKEN": token}),
            ):
                original = self.native.side_effect

                def native(argv, original=original, **kwargs):
                    result = original(argv, **kwargs)
                    if argv[0] == self.platform["curl"]:
                        result.stdout = f"public output {token} glrt-fixture-pattern"
                        result.stderr = "public error glrtr-other-pattern"
                    return result

                self.native.side_effect = native
                code, stdout, stderr = self.invoke(verbose=verbose)
                self.native.side_effect = original
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                for text in ("stdout:", "stderr:", "public output", "public error", "<redacted>"):
                    self.assertIn(text, stderr)
                for secret in (token, "glrt-fixture-pattern", "glrtr-other-pattern"):
                    self.assertNotIn(secret, stderr)
                self.assertNotIn(self.platform["curl"], stderr)

    def test_curl_proxy_and_uri_credentials_are_redacted_in_both_modes(self):
        original = "http://fixture-user:fixture-password@proxy.example:bad-port"
        uri = "https://another-user:another-password@gitlab.example/health"
        self.prerequisites(code=7)
        native = self.native.side_effect

        def proxy_failure(argv, **kwargs):
            result = native(argv, **kwargs)
            if argv[0] == self.platform["curl"]:
                result.stderr = f"Unsupported proxy syntax in '{original}'; request {uri}"
            return result

        self.native.side_effect = proxy_failure
        for verbose in (False, True):
            with (
                self.subTest(verbose=verbose),
                mock.patch.dict(os.environ, {"HTTPS_PROXY": original}),
            ):
                code, stdout, stderr = self.invoke(verbose=verbose)
                self.assertEqual(code, 1)
                self.assertIn("Unsupported proxy syntax", stderr)
                self.assertIn("<redacted>", stderr)
                for credential in (
                    "fixture-user",
                    "fixture-password",
                    "another-user",
                    "another-password",
                ):
                    self.assertNotIn(credential, stdout + stderr)

    def test_timeout_preserves_byte_streams_without_arguments(self):
        self.prerequisites(
            subprocess.TimeoutExpired(
                ["fake", "private-argument"],
                1,
                output=b"partial output glrt-fixture-token",
                stderr=b"partial error\xff",
            )
        )
        for verbose in (False, True):
            with self.subTest(verbose=verbose):
                code, stdout, stderr = self.invoke(verbose=verbose)
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("partial output <redacted>", stderr)
                self.assertIn("partial error\ufffd", stderr)
                self.assertNotIn("private-argument", stderr)

    def test_startup_failure_hides_exception_filename_and_arguments(self):
        self.prerequisites(FileNotFoundError("private-path-and-argument"))
        code, _, stderr = self.invoke(verbose=True)
        self.assertEqual(code, 1)
        self.assertIn("command could not start: curl (FileNotFoundError)", stderr)
        self.assertNotIn("private-path-and-argument", stderr)

    def test_unchecked_failure_preserves_streams_before_existing_classification(self):
        self.native.return_value = subprocess.CompletedProcess(
            [], 2, "public output", "public error"
        )
        self.native.side_effect = None
        code, _, stderr = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("public output", stderr)
        self.assertIn("public error", stderr)
        self.assertIn("required network interface is missing", stderr)

    def test_verbose_success_uses_stderr_and_does_not_leak_to_next_invocation(self):
        self.prerequisites()
        code, stdout, stderr = self.invoke(verbose=True)
        self.assertEqual(code, 0)
        self.assertEqual(stdout, "frontend: prerequisites ready\n")
        self.assertIn("+ curl", stderr)
        self.assertIn("public output", stderr)
        self.assertFalse(diagnostics.verbose())
        code, _, stderr = self.invoke()
        self.assertEqual(code, 0)
        self.assertNotIn("+ curl", stderr)
        self.assertNotIn("public output", stderr)
        self.assertFalse(diagnostics.verbose())

    def test_sensitive_command_streams_are_suppressed_even_when_verbose(self):
        def prerequisite(_instance, _platform):
            operations.run(["fake", "private-argument"], capture=False)

        self.stack.enter_context(
            mock.patch.object(operations, "check_prerequisites", side_effect=prerequisite)
        )
        for outcome in (
            subprocess.CompletedProcess([], 0, "private-output", "private-error"),
            subprocess.CompletedProcess([], 1, "private-output", "private-error"),
            subprocess.TimeoutExpired([], 1, output="private-output", stderr="private-error"),
        ):
            for verbose in (False, True):
                with self.subTest(outcome=type(outcome).__name__, verbose=verbose):
                    self.native.side_effect = outcome if isinstance(outcome, Exception) else None
                    self.native.return_value = outcome
                    code, stdout, stderr = self.invoke(verbose=verbose)
                    self.assertEqual(
                        code, 1 if isinstance(outcome, Exception) else outcome.returncode
                    )
                    self.assertNotIn("private-", stdout + stderr)

    def test_expected_absence_stays_quiet_but_raw_query_output_survives(self):
        def prerequisite(_instance, _platform):
            result = operations.run(
                ["fake"], capture=True, check=False, public=True, expected=(0, 1)
            )
            self.assertEqual(result.stdout, "absent")
            self.assertEqual(result.stderr, "expected absence")

        self.stack.enter_context(
            mock.patch.object(operations, "check_prerequisites", side_effect=prerequisite)
        )
        self.native.side_effect = None
        self.native.return_value = subprocess.CompletedProcess([], 1, "absent", "expected absence")
        code, _, stderr = self.invoke()
        self.assertEqual(code, 0)
        self.assertNotIn("expected absence", stderr)

    def test_verbose_plan_keeps_json_stdout_and_check_forwards_progress_mode(self):
        progress = operations.Progress
        self.stack.enter_context(mock.patch.object(operations, "inspect_policy", return_value=[]))
        with mock.patch.object(operations, "Progress", wraps=progress) as rendered:
            code, stdout, _ = self.invoke("plan", verbose=True, extra=("--json",))
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout), [])
            self.prerequisites()
            self.assertEqual(self.invoke(verbose=True)[0], 0)
        self.assertTrue(rendered.call_args.kwargs["verbose"])

    def prepare_verification(self):
        entry = pwd.struct_passwd(("fixture", "x", 1001, 1001, "", "/fixture", "/bin/bash"))
        for name in ("required_interface_is_up", "verify_rootless_podman", "verify_aardvark"):
            self.stack.enter_context(mock.patch.object(operations, name))
        self.stack.enter_context(mock.patch.object(operations.pwd, "getpwnam", return_value=entry))
        self.stack.enter_context(mock.patch.object(Path, "exists", return_value=True))
        self.stack.enter_context(mock.patch.object(Path, "stat"))
        self.stack.enter_context(mock.patch.object(operations.stat, "S_ISSOCK", return_value=True))
        self.stack.enter_context(
            mock.patch.object(
                operations, "registration_metadata", return_value={"token": "fixture"}
            )
        )
        self.stack.enter_context(
            mock.patch.object(operations, "inspect_manager", return_value="matches-declaration")
        )
        self.stack.enter_context(mock.patch.object(operations, "operation_lock"))

    def test_gitlab_verification_and_lint_never_opt_into_public_output(self):
        self.prepare_verification()
        for lint in (False, True):
            for verbose in (False, True):
                with self.subTest(lint=lint, verbose=verbose):

                    def native(argv, lint=lint, **_kwargs):
                        if self.platform["systemctl"] in argv:
                            return subprocess.CompletedProcess(argv, 0, "active", "")
                        self.assertIn("exec", argv)
                        if argv[-1] == "--help":
                            return subprocess.CompletedProcess(
                                argv, 0, "  lint  check" if lint else "", ""
                            )
                        self.assertIn("lint" if lint else "verify", argv)
                        return subprocess.CompletedProcess(
                            argv, 1, "private-output", "private-error"
                        )

                    self.native.side_effect = native
                    code, stdout, stderr = self.invoke("verify", verbose=verbose)
                    self.assertEqual(code, 1)
                    self.assertNotIn("private-", stdout + stderr)

    def test_verbose_purge_hides_rejected_socket_execution_properties(self):
        real_run, real_run_as = operations.run, operations.run_as
        fixture = retirement_support.RetirementCliTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original = fixture.properties
        secret = "fixture-legacy-hook-credential"

        def properties(unit):
            values = original(unit)
            if unit == "podman.socket":
                values["ExecStopPre"] = "/fake/command --password=" + secret
            return values

        def native(argv, **_kwargs):
            index = argv.index(fixture.f.platform["systemctl"])
            return fixture.native(fixture.f.entry, argv[index:], platform=fixture.f.platform)

        fixture.properties = properties
        fixture.f.command = "purge"
        arguments = [
            "runnerctl",
            "--verbose",
            "--platform",
            "arch",
            "-c",
            str(fixture.f.input),
            "purge",
            "frontend",
        ]
        stdout, stderr = StringIO(), StringIO()
        with (
            mock.patch.object(operations, "run", real_run),
            mock.patch.object(operations, "run_as", real_run_as),
            mock.patch.object(operations.subprocess, "run", side_effect=native),
            mock.patch.object(sys, "argv", arguments),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as exited,
        ):
            cli.main_cli()
        self.assertEqual(exited.exception.code, 1)
        self.assertIn("refuse Podman socket stop hooks", stderr.getvalue())
        self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
        self.assertFalse(any("stop" in args for args in fixture.calls))

    def test_registration_retains_devnull_output_in_verbose_mode(self):
        self.prepare_verification()
        self.stack.enter_context(
            mock.patch.dict(os.environ, {"GITLAB_RUNNER_TOKEN": "glrt-fixture"})
        )
        self.stack.enter_context(
            mock.patch.object(operations, "registration_metadata", return_value={})
        )

        def native(argv, **kwargs):
            self.assertIn("register", argv)
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertNotIn("glrt-fixture", argv)
            return subprocess.CompletedProcess(argv, 1)

        self.native.side_effect = native
        for verbose in (False, True):
            code, stdout, stderr = self.invoke("register", verbose=verbose)
            self.assertEqual(code, 1)
            self.assertNotIn("glrt-fixture", stdout + stderr)
