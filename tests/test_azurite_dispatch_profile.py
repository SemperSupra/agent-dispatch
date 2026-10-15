"""Fixed Azurite transport admission; preserves existing public actor authority limits."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gha_workload_request as req
import gha_assignment_contract as admission

MANIFEST = "requests/gha/azurite-blob-transport-v1.json"
SHA = "a" * 40
RUN = "123456789"


class AzuriteWorkcellTests(unittest.TestCase):
    def test_exact_static_profile(self):
        p = req.plan(MANIFEST)
        self.assertEqual(p["runner"], "ubuntu-24.04")
        self.assertEqual(p["workload"], "azurite-blob-transport")
        self.assertEqual(p["data_class"], "public-synthetic")
        self.assertEqual(p["max_attempts"], 1)
        self.assertEqual(p["max_cost_usd"], 0)
        self.assertLessEqual(p["timeout_seconds"], 240)
        self.assertEqual(admission.PROFILES["azurite-blob-transport-v1"], MANIFEST)
        source, sha = req.read_request(MANIFEST)
        self.assertEqual(set(source), req.FIELDS)
        self.assertEqual(p["request_sha256"], sha)
        for word in ("command", "shell", "secret", "token", "url", "image", "account"):
            self.assertNotIn(word, source)

    def test_fixed_command_and_mock_authority_constraints(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "azurite-blob"
            folder.mkdir()
            verdict = {
                "schema": "azurite-transport-independent-verdict/v1",
                "classification": "EMULATOR_ONLY_PASS",
                "provider_access_verified": False,
                "revision_changed": True,
                "write_replay_blocked": True,
                "stale_write_blocked": True,
                "stale_read_blocked": True,
                "fresh_client_recovered": True,
                "source_sha": SHA,
                "native_run_id": RUN,
            }
            (folder / "verified.json").write_text(json.dumps(verdict))
            with patch.object(req.subprocess, "run", return_value=MagicMock(returncode=0)) as sub, \
                 patch.dict(os.environ, {"RUNNER_TEMP": td, "GITHUB_SHA": SHA,
                                         "GITHUB_RUN_ID": RUN}):
                result = req._execute("azurite-blob-transport", 180)
                self.assertTrue(result["oracle_verified"])
                self.assertTrue(result["emulator_only"])
                self.assertIs(result["provider_access_verified"], False)
                self.assertEqual(result["classification"], "PASS")
                sub.assert_called_once()
                self.assertEqual(sub.call_args.args[0], ["bash", "scripts/qualify_azurite_transport.sh"])
                self.assertNotIn("shell", sub.call_args.kwargs)
                for bad in (
                    {"provider_access_verified": True},
                    {"source_sha": "b" * 40},
                    {"native_run_id": "123"},
                    {"stale_write_blocked": False},
                    {"revision_changed": False},
                    {"fresh_client_recovered": False},
                ):
                    with self.subTest(bad=bad):
                        forged = dict(verdict, **bad)
                        (folder / "verified.json").write_text(json.dumps(forged))
                        actual = req._execute("azurite-blob-transport", 180)
                        self.assertFalse(actual["oracle_verified"])
                        self.assertIsNone(actual["verdict_sha256"])

    def test_missing_verdict_and_process_fail_are_rejected(self):
        with tempfile.TemporaryDirectory() as td, \
             patch.object(req.subprocess, "run", return_value=MagicMock(returncode=2)), \
             patch.dict(os.environ, {"RUNNER_TEMP": td, "GITHUB_SHA": SHA,
                                     "GITHUB_RUN_ID": RUN}):
            result = req._execute("azurite-blob-transport", 180)
            self.assertFalse(result["oracle_verified"])
            self.assertEqual(result["classification"], "FAIL_EMULATOR")

    def test_no_external_network_and_version_drift_in_script(self):
        sh = (ROOT / "scripts" / "qualify_azurite_transport.sh").read_text()
        self.assertIn("mcr.microsoft.com/azure-storage/azurite@sha256:", sh)
        self.assertIn("docker network create --driver bridge --internal", sh)
        self.assertNotIn("docker logs", sh)
        self.assertNotIn("login.microsoftonline.com", sh)
        self.assertNotIn(" -p 10000:10000", sh)


if __name__ == "__main__":
    unittest.main()
