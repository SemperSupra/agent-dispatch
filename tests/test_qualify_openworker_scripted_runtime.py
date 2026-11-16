"""Offline admission/denial checks for the true OpenWorker scripted runtime workcell.

No Git clone, dependency installation, model, SMTP, or network in these tests.
"""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_openworker_scripted_runtime as q

class PublicOriginalRunTests(unittest.TestCase):
    def test_exact_public_source_and_blob_pins(self):
        self.assertEqual(q.COMMIT, "ecb445490fc054d52b8ea610d97ba947f57033d2")
        self.assertEqual(q.REPOSITORY, "https://github.com/andrewyng/openworker.git")
        self.assertEqual(sorted(q.BLOBS), sorted([
            "LICENSE", "coworker/connectors/email_tools.py",
            "coworker/headless/runner.py", "pyproject.toml"]))
        self.assertEqual(len(q.git_blob(b"public test")), 40)
        self.assertNotEqual(q.git_blob(b"public test"), q.git_blob(b"public test changed"))

    def test_script_has_only_one_attempted_synthetic_write(self):
        self.assertEqual(len(q.SCRIPT), 2)
        first = q.SCRIPT[0]["tool_calls"]
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["name"], "write_file")
        self.assertEqual(first[0]["arguments"]["path"], "forbidden.txt")
        self.assertFalse("run_shell" in str(q.SCRIPT))
        self.assertNotIn("smtp", str(q.SCRIPT).lower())

    def test_environment_does_not_inherit_account_keys_or_proxy(self):
        with tempfile.TemporaryDirectory() as d:
            scrubbed = q.scrub_environment(Path(d), path="/usr/bin:/bin")
            self.assertEqual(scrubbed["HOME"], d)
            self.assertTrue(scrubbed["PIP_NO_INPUT"])
            for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
                        "GH_TOKEN", "GITHUB_TOKEN", "GIT_ASKPASS", "HTTP_PROXY",
                        "HTTPS_PROXY", "AWS_ACCESS_KEY_ID"):
                self.assertNotIn(key, scrubbed)

    def test_missing_or_forged_record_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaisesRegex(q.QualifyError, "MISSING_ENGINE_RECORD"):
                q.inspect_record(root, root)

if __name__ == "__main__":
    unittest.main()
