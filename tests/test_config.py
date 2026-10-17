"""Instance files: loading, inheritance, schema and declaration validation."""

from __future__ import annotations

import copy
from pathlib import Path
import shutil
import tempfile
import unittest

from runner_config import load_instances
from runner_model import RunnerError, validate_instances

FIXTURES = Path(__file__).parent / "fixtures"


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in ("common.toml", "frontend.toml", "dotnet.toml"):
            shutil.copy(FIXTURES / name, self.root)

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text)
        return path

    def load(self, *names: str):
        return load_instances([self.root / name for name in names])

    def test_file_stem_names_the_instance_and_base_values_are_inherited(self) -> None:
        instances = self.load("frontend.toml", "dotnet.toml")
        self.assertEqual(sorted(instances), ["dotnet", "frontend"])
        frontend = instances["frontend"]
        self.assertEqual(frontend["account"]["user"], "gitlab-runner-frontend")
        self.assertEqual(frontend["gitlab"]["url"], "https://gitlab.example")
        self.assertEqual(frontend["network"]["requiredInterface"], "tailscale0")
        validate_instances(instances)

    def test_instance_values_override_the_base(self) -> None:
        self.write(
            "frontend.toml",
            (self.root / "frontend.toml").read_text() + '\n[network]\ndns = "192.0.2.53"\n',
        )
        network = self.load("frontend.toml")["frontend"]["network"]
        self.assertEqual(network, {"requiredInterface": "tailscale0", "dns": "192.0.2.53"})

    def test_certificate_paths_resolve_relative_to_the_declaring_file(self) -> None:
        (self.root / "shared").mkdir()
        (self.root / "shared/ca.crt").write_text("certificate")
        self.write(
            "shared/base.toml",
            (self.root / "common.toml")
            .read_text()
            .replace("[gitlab]\n", '[gitlab]\nca_certificate = "ca.crt"\n'),
        )
        self.write(
            "frontend.toml",
            (self.root / "frontend.toml")
            .read_text()
            .replace('extends = "common.toml"', 'extends = "shared/base.toml"'),
        )
        instances = self.load("frontend.toml")
        self.assertEqual(
            instances["frontend"]["gitlab"]["caCertificate"], str(self.root / "shared/ca.crt")
        )
        self.assertIn("tls-ca-file", instances["frontend"]["artifacts"]["configPolicy"]["caLine"])
        validate_instances(instances)

    def test_invalid_files_are_rejected_with_their_cause(self) -> None:
        frontend = (self.root / "frontend.toml").read_text()
        for name, text, message in (
            ("frontend.toml", frontend + "typo = 1\n", "unknown key: typo"),
            ("frontend.toml", frontend.replace("uid = 1001", 'uid = "1001"'), "uid must be"),
            ("frontend.toml", frontend.replace("uid = 1001", "uid = true"), "uid must be"),
            ("frontend.toml", frontend.replace("uid = 1001\n", ""), "missing required key: uid"),
            ("frontend.toml", frontend.replace("[runner]", "[runner]\nextra = 1"), "unknown key"),
            ("frontend.toml", frontend + "[gitlab]\nurl = 1\n", "gitlab.url must be a str"),
            ("frontend.toml", frontend + "= broken\n", "not valid TOML"),
            ("Frontend.toml", frontend, "invalid instance name"),
            ("frontend.json", frontend, "must be a .toml"),
            (
                "frontend.toml",
                frontend.replace('extends = "common.toml"', 'extends = "missing.toml"'),
                "cannot read",
            ),
        ):
            with self.subTest(name=name, message=message):
                path = self.write(name, text)
                with self.assertRaisesRegex(RunnerError, message):
                    load_instances([path])
                path.unlink()

    def test_a_base_cannot_extend_another_file(self) -> None:
        self.write(
            "common.toml", 'extends = "other.toml"\n' + (self.root / "common.toml").read_text()
        )
        with self.assertRaisesRegex(RunnerError, "cannot extend"):
            self.load("frontend.toml")

    def test_unsupported_provider_is_rejected(self) -> None:
        self.write(
            "common.toml",
            (self.root / "common.toml").read_text().replace('"gitlab"', '"github"', 1),
        )
        with self.assertRaisesRegex(RunnerError, "unsupported provider: github"):
            self.load("frontend.toml")

    def test_one_instance_per_name(self) -> None:
        (self.root / "other").mkdir()
        shutil.copy(self.root / "frontend.toml", self.root / "other/frontend.toml")
        shutil.copy(self.root / "common.toml", self.root / "other/common.toml")
        with self.assertRaisesRegex(RunnerError, "more than one file"):
            self.load("frontend.toml", "other/frontend.toml")

    def test_colliding_ids_across_files_are_rejected(self) -> None:
        self.write(
            "dotnet.toml",
            (self.root / "dotnet.toml").read_text().replace("uid = 1002", "uid = 1001"),
        )
        with self.assertRaisesRegex(RunnerError, "UIDs must be unique"):
            validate_instances(self.load("frontend.toml", "dotnet.toml"))

    def test_declared_values_are_validated(self) -> None:
        base = self.load("frontend.toml")["frontend"]
        for section, key, value, valid in (
            ("network", "dns", "999.1.1.1", False),
            ("network", "dns", "1.2.3", False),
            ("network", "dns", "01.2.3.4", False),
            ("network", "dns", "2001:db8::1", True),
            ("network", "dns", "::ffff:192.0.2.1", True),
            ("network", "dns", "1::2::3", False),
            ("network", "dns", None, True),
            ("runner", "cpus", "0", False),
            ("runner", "cpus", "0.5", True),
            ("runner", "memory", "0g", False),
            ("runner", "name", "", False),
            ("runner", "defaultJobImage", "docker.io/library/node:latest", False),
            ("runner", "allowedImages", [], False),
            ("gitlab", "healthUrl", "https://other.example/", False),
            ("gitlab", "caCertificate", str(self.root / "missing.crt"), False),
        ):
            with self.subTest(key=key, value=value):
                instance = copy.deepcopy(base)
                instance[section][key] = value
                if valid:
                    validate_instances({"frontend": instance})
                else:
                    with self.assertRaises(RunnerError):
                        validate_instances({"frontend": instance})


if __name__ == "__main__":
    unittest.main()
