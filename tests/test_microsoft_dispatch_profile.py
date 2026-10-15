"""Microsoft mock profile is a fixed public-safe Agent Dispatch workload, not dynamic shell."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
import gha_workload_request as req
import gha_assignment_contract as admission
from microsoft_devproxy_contract import IMAGE


PATH = "requests/gha/microsoft-devproxy-mock-v1.json"
SOURCE = "a"*40
RUN = "123"


class MicrosoftDispatchProfileTests(unittest.TestCase):
    def test_exact_reviewed_profile_and_assignment_mapping(self):
        p = req.plan(PATH)
        self.assertEqual(p["workload"], "microsoft-devproxy-mock")
        self.assertEqual(p["runner"], "ubuntu-24.04")
        self.assertEqual(p["max_cost_usd"], 0)
        self.assertEqual(p["max_attempts"], 1)
        self.assertEqual(p["data_class"], "public-synthetic")
        self.assertLessEqual(p["timeout_seconds"], 240)
        self.assertEqual(admission.PROFILES["microsoft-devproxy-mock-v1"], PATH)
        self.assertEqual(len(p["request_sha256"]), 64)

    def test_nothing_dynamic_comes_from_untrusted_work_request(self):
        source, _digest = req.read_request(PATH)
        self.assertEqual(set(source), req.FIELDS)
        self.assertNotIn("command", source)
        self.assertNotIn("secret", source)
        self.assertNotIn("url", source)
        self.assertNotIn("token", source)

    def test_fixed_subprocess_and_independent_verdict_required(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)/"microsoft-mock"
            out.mkdir()
            expected = {"classification":"MOCK_ONLY_PASS", "verified": True,
                        "provider_access_verified": False,
                        "source_sha":SOURCE, "run_id":RUN}
            (out/"verified.json").write_text(json.dumps(expected))
            with patch.object(req.subprocess, "run", return_value=MagicMock(returncode=0)) as run, \
                 patch.dict(os.environ, {"RUNNER_TEMP":td,"GITHUB_SHA":SOURCE,
                                         "GITHUB_RUN_ID":RUN}):
                positive = req._execute("microsoft-devproxy-mock", 180)
                self.assertTrue(positive["oracle_verified"])
                self.assertTrue(positive["mock_only"])
                self.assertFalse(positive["provider_access_verified"])
                self.assertEqual(positive["classification"], "PASS")
                run.assert_called_once()
                argv = run.call_args.args[0]
                self.assertEqual(argv, ["bash", "scripts/qualify_microsoft_devproxy.sh"])
                self.assertNotIn("shell", run.call_args.kwargs)

                expected["provider_access_verified"] = True
                (out/"verified.json").write_text(json.dumps(expected))
                rejected = req._execute("microsoft-devproxy-mock", 180)
                self.assertFalse(rejected["oracle_verified"])
                self.assertEqual(rejected["classification"], "FAIL_MOCK_VERDICT")

    def test_missing_verdict_and_nonzero_exit_not_admitted(self):
        with tempfile.TemporaryDirectory() as td, \
             patch.dict(os.environ, {"RUNNER_TEMP":td,"GITHUB_SHA":SOURCE,
                                     "GITHUB_RUN_ID":RUN}), \
             patch.object(req.subprocess, "run", return_value=MagicMock(returncode=1)):
            negative = req._execute("microsoft-devproxy-mock", 180)
            self.assertFalse(negative["oracle_verified"])
            self.assertEqual(negative["classification"], "FAIL_MOCK_CANARY")
            self.assertIsNone(negative["verdict_sha256"])

    def test_image_digest_is_fixed_not_latest(self):
        self.assertIn("@sha256:", IMAGE)
        self.assertNotIn(":latest", IMAGE)


if __name__ == "__main__":
    unittest.main()
