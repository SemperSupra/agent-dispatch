"""Offline-first adversarial tests for immutable OpenWorker source qualification."""
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_openworker_headless_mail as q


class OriginalConnectorHarnessTests(unittest.TestCase):
    def test_source_paths_commit_and_license_pins(self):
        self.assertEqual(q.COMMIT, "ecb445490fc054d52b8ea610d97ba947f57033d2")
        self.assertEqual(sorted(q.SOURCES), ["LICENSE", "coworker/connectors/email_tools.py",
                                            "coworker/headless/runner.py"])
        self.assertTrue(q.BASE.startswith("https://raw.githubusercontent.com/andrewyng/openworker/"))
        with self.assertRaisesRegex(q.Refused, "UNREVIEWED_PUBLIC_SOURCE"):
            q.acquire("../private/mail.pst")

    def test_git_blob_mutation_changes_identity(self):
        original = b"synthetic fake mail only"
        self.assertEqual(len(q.git_blob_hash(original)), 40)
        self.assertNotEqual(q.git_blob_hash(original),
                            q.git_blob_hash(original + b" edited"))

    def test_fake_messages_are_distinct_even_with_same_message_id(self):
        source = q.fixture_messages()
        self.assertEqual(sorted(source), ["7", "8"])
        self.assertEqual(source["7"]["Message-ID"], source["8"]["Message-ID"])
        self.assertNotEqual(source["7"]["Subject"], source["8"]["Subject"])
        files = [p for p in source["7"].walk() if p.get_filename()]
        self.assertEqual([p.get_filename() for p in files], ["report.txt", "report.txt"])
        self.assertNotEqual(files[0].get_payload(decode=True),
                            files[1].get_payload(decode=True))

    def test_fake_imap_tracks_readonly_and_peek(self):
        m = q.FakeIMAP(q.fixture_messages())
        with self.assertRaises(AssertionError):
            m.login("not-an-allowed-fake@invalid.test", "not-a-fake")
        m.login("fictional@icloud.com", "synthetic-test-only")
        m.select('"INBOX"', readonly=True)
        status, chunks = m.uid("FETCH", "7", "(BODY.PEEK[])")
        self.assertEqual(status, "OK")
        self.assertIn(b"Fictional mail", chunks[0][1])
        self.assertTrue(m.calls[-2][2])
        self.assertEqual(m.calls[-1][3], "(BODY.PEEK[])")
        m.logout()
        self.assertTrue(m.logout_called)

    def test_fake_secret_store_is_only_synthetic_identity(self):
        s = q.FakeStore()
        self.assertEqual(s.get("email:default"), {})
        with self.assertRaisesRegex(AssertionError, "UNREVIEWED_CREDENTIAL_NAME"):
            s.get("work:secret")
        self.assertEqual(q.FakeStore({"address": "dummy@invalid.test"}).get(
            "email:default")["address"], "dummy@invalid.test")


if __name__ == "__main__":
    unittest.main()
