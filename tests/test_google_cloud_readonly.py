"""No-credential negative tests for the pinned read-only Google execution shape."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts" / "google_cloud_readonly.py"
spec = importlib.util.spec_from_file_location("google_cloud_readonly", SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class GoogleReadonlyTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            **mod.EXPECTED,
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "999",
            "GOOGLE_RO_PROJECT_ID": "sample-12345",
        }

    def test_exact_context(self):
        self.assertTrue(mod.admitted(self.env))

    def test_each_context_field_required(self):
        for field in mod.EXPECTED:
            with self.subTest(field=field):
                self.assertFalse(mod.admitted({**self.env, field: "other"}))
                absent = dict(self.env)
                absent.pop(field)
                self.assertFalse(mod.admitted(absent))

    def test_no_pr_fork_tag_other_workflow_or_retry(self):
        for key, value in (
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REPOSITORY", "attacker/agent-dispatch"),
            ("GITHUB_REPOSITORY_ID", "1350205858"),
            ("GITHUB_REPOSITORY_OWNER_ID", "68664497"),
            ("GITHUB_REF", "refs/tags/release"),
            ("GITHUB_WORKFLOW_REF", "SemperSupra/agent-dispatch/.github/workflows/gha-typed-public-cpu.yml@refs/heads/main"),
            ("GITHUB_RUN_ATTEMPT", "2"),
        ):
            self.assertFalse(mod.admitted({**self.env, key: value}))

    def test_missing_or_bad_run_id_sha(self):
        self.assertFalse(mod.admitted({**self.env, "GITHUB_RUN_ID": "0"}))
        self.assertFalse(mod.admitted({**self.env, "GITHUB_RUN_ID": "1/2"}))
        self.assertFalse(mod.admitted({**self.env, "GITHUB_SHA": "not-a-sha"}))

    def test_never_probe_unadmitted_context(self):
        with tempfile.TemporaryDirectory() as td, patch.object(mod.subprocess, "run", side_effect=AssertionError("called")):
            self.assertEqual(mod.probe({**self.env, "GITHUB_EVENT_NAME": "pull_request"}, Path(td) / "receipt.json"), 2)

    def test_not_probe_with_invalid_project_id(self):
        with tempfile.TemporaryDirectory() as td, patch.object(mod.subprocess, "run", side_effect=AssertionError("called")):
            self.assertEqual(mod.probe({**self.env, "GOOGLE_RO_PROJECT_ID": "123/evil"}, Path(td) / "receipt.json"), 2)

    def test_success_probe_suppresses_all_project_metadata(self):
        class Result:
            returncode = 0
            stdout = '{"projectNumber":"123456789012","private_data":"token secret"}'
            stderr = ""
        with tempfile.TemporaryDirectory() as td, patch.object(mod.subprocess, "run", return_value=Result()):
            path = Path(td) / "receipt.json"
            self.assertEqual(mod.probe(self.env, path), 0)
            output = path.read_text()
            self.assertNotIn("123456789012", output)
            self.assertNotIn("sample-12345", output)
            self.assertNotIn("token secret", output)
            self.assertEqual(mod.verify(path, self.env), 0)

    def test_failed_provider_never_publishes_stderr_or_receipt(self):
        class Result:
            returncode = 1
            stdout = ""
            stderr = "account email@example.com token sensitive"
        with tempfile.TemporaryDirectory() as td, patch.object(mod.subprocess, "run", return_value=Result()):
            dest = Path(td) / "receipt.json"
            self.assertEqual(mod.probe(self.env, dest), 3)
            self.assertFalse(dest.exists())

    def test_receipt_exact_fields_and_run_binding(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = {
                "schema_version": 1,
                "status": "verified",
                "source_sha": self.env["GITHUB_SHA"],
                "run_id": self.env["GITHUB_RUN_ID"],
                "run_attempt": 1,
                "repository_id": self.env["GITHUB_REPOSITORY_ID"],
                "event_name": "workflow_dispatch",
                "project_metadata_verified": True,
            }
            path = Path(td) / "receipt.json"
            for bad in (
                {**receipt, "access_token": "secret"},
                {**receipt, "source_sha": "b" * 40},
                {**receipt, "run_id": "998"},
                {**receipt, "run_attempt": 2},
                {**receipt, "project_metadata_verified": False},
            ):
                self.assertFalse(mod.validate_receipt(bad, self.env))
            self.assertTrue(mod.validate_receipt(receipt, self.env))

    def test_duplicate_key_receipt_denied(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            path.write_text('{"run_id":"999","run_id":"998"}')
            self.assertEqual(mod.verify(path, self.env), 4)

    def test_bool_attempt_denied(self):
        receipt = {
            "schema_version": 1,
            "status": "verified",
            "source_sha": self.env["GITHUB_SHA"],
            "run_id": self.env["GITHUB_RUN_ID"],
            "run_attempt": True,
            "repository_id": self.env["GITHUB_REPOSITORY_ID"],
            "event_name": "workflow_dispatch",
            "project_metadata_verified": True,
        }
        self.assertFalse(mod.validate_receipt(receipt, self.env))

    def test_invalid_receipt_fails(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "r.json"
            path.write_text('{"token":"secret"}')
            self.assertEqual(mod.verify(path, self.env), 4)


if __name__ == "__main__":
    unittest.main()
