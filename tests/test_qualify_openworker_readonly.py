"""Zero-network adversarial tests for pinned public OpenWorker source qualifier."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_openworker_readonly as upstream


class OpenWorkerSourceAdmissionTests(unittest.TestCase):
    def test_reject_unknown_paths_before_network(self):
        with self.assertRaisesRegex(upstream.QualificationError, "UNREVIEWED_PATH"):
            upstream.download("../private/.env")
        self.assertEqual(upstream.COMMIT,
                         "ecb445490fc054d52b8ea610d97ba947f57033d2")

    def test_exact_git_blob_identity(self):
        source = b'"""synthetic public module"""\n'
        sha = upstream.git_blob_sha(source)
        with patch.dict(upstream.SOURCES, {"mock/module.py": sha}):
            upstream.verify_bytes("mock/module.py", source)
            with self.assertRaisesRegex(upstream.QualificationError,
                                        "PINNED_UPSTREAM_GIT_BLOB_MISMATCH"):
                upstream.verify_bytes("mock/module.py", source + b"# changed")

    def test_nonexistent_and_oversized_source_denied(self):
        source = b"some unsafe contents" * 5000
        with self.assertRaisesRegex(upstream.QualificationError,
                                    "UPSTREAM_CONTENT_NOT_ALLOWED"):
            upstream.verify_bytes("LICENSE", source)
        with self.assertRaisesRegex(upstream.QualificationError,
                                    "UPSTREAM_CONTENT_NOT_ALLOWED"):
            upstream.verify_bytes("unrecognized.py", b"valid bytes " * 5)

    def test_no_permissive_url_or_secret_source(self):
        self.assertEqual(sorted(upstream.SOURCES),
                         ["LICENSE", "coworker/readonly.py",
                          "coworker/sandbox/network_profiles.py"])
        self.assertTrue(upstream.BASE.startswith(
            "https://raw.githubusercontent.com/andrewyng/openworker/"))
        self.assertNotIn("token", upstream.BASE)
        self.assertNotIn("http://", upstream.BASE)

    def test_real_probe_requires_safe_and_denied_cases(self):
        class Reviewer:
            @staticmethod
            def is_readonly_command(command, shell):
                return not any(x in command for x in
                               ("rm", "curl", "python3 -c", ">"))
        class Profiles:
            @staticmethod
            def clean_host(value):
                return "example.invalid:443"
            @staticmethod
            def check(value):
                raise ValueError("profile")
        d = upstream.run_case_matrix(Reviewer, Profiles)
        self.assertEqual(d["allowed_controls"], 2)
        self.assertEqual(d["blocked_controls"], 6)
        self.assertTrue(d["dangerous_all_rejected"])
        self.assertTrue(d["safe_all_allowed"])


if __name__ == "__main__":
    unittest.main()
