"""Offline, public-source-only admission checks for pinned ResMed parser bakeoff."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "public_cpap_parser_bakeoff.py"
spec = importlib.util.spec_from_file_location("public_cpap_parser_bakeoff", SCRIPT)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PublicCpapParserBakeoff(unittest.TestCase):
    def test_fixed_public_upstream_sha_and_mit_source(self):
        self.assertEqual(p.UPSTREAM, "https://github.com/hms-homelab/hms-cpapdash-parser.git")
        self.assertEqual(p.SHA, "d14acb58012449af75b0c15c0bfb1eb173b60a1f")
        self.assertEqual(p.SCHEMA, "public-cpap-format-bakeoff/v1")

    def test_only_in_memory_generated_synthetic_suites_are_allowed(self):
        self.assertEqual(p.TEST_FILTER, "EDFFileTest.*:EDFParserHardening.*:"
                         "EveMultiBlock.*:STRFamily.*:AirSense11Summary.*:EdfRecordCount.*")
        self.assertNotIn("OximetryCsv", p.TEST_FILTER)
        self.assertNotIn("donor", p.TEST_FILTER.lower())

    def test_host_must_be_public_unprivileged_and_matching_architecture(self):
        with tempfile.TemporaryDirectory() as d:
            for env in ({}, {"GITHUB_REPOSITORY": "private/clinical", "RUNNER_ARCH": "X64"},
                        {"GITHUB_REPOSITORY": "SemperSupra/agent-dispatch", "RUNNER_ARCH": "unknown"}):
                with self.subTest(env=env), mock.patch.dict(p.os.environ, env, clear=True):
                    with self.assertRaises(p.NotQualified):
                        p.run(Path(d) / "receipt.json")
            with mock.patch.dict(p.os.environ, {"GITHUB_REPOSITORY": "SemperSupra/agent-dispatch",
                                                "RUNNER_ARCH": "X64"}), \
                 mock.patch.object(p.platform, "machine", return_value="aarch64"):
                with self.assertRaises(p.NotQualified):
                    p.run(Path(d) / "receipt.json")

    def test_shell_and_dynamic_code_paths_are_not_present(self):
        source = SCRIPT.read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)
        self.assertNotIn("shutil.copytree", source)
        self.assertNotIn("GITHUB_TOKEN", source)
        self.assertNotIn("PAT_TOKEN", source)

    def test_failed_fixed_command_rejected(self):
        fail = subprocess.CompletedProcess(["git"], 1, stdout=b"", stderr=b"unavailable")
        with mock.patch.object(p.subprocess, "run", return_value=fail):
            with self.assertRaisesRegex(p.NotQualified, "command failed"):
                p.command(["git", "rev-parse", "HEAD"])
        with self.assertRaises(p.NotQualified):
            p.command([])

    def test_oversized_successful_output_rejected(self):
        huge = subprocess.CompletedProcess(["gtest"], 0,
                                           stdout=b"S" * (p.MAX_BYTES + 1), stderr=b"")
        with mock.patch.object(p.subprocess, "run", return_value=huge):
            with self.assertRaisesRegex(p.NotQualified, "command failed"):
                p.command(["gtest", "--gtest_brief=1"])


if __name__ == "__main__":
    unittest.main()
