"""Independent zero-network negative controls for pinned RAG-Mail MBOX witness."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_ragmail_mbox_loss as witness


class RAGMailSourceWitnessTests(unittest.TestCase):
    def test_pinned_source_rights_and_limited_origin(self):
        self.assertEqual(witness.COMMIT,
                         "afab46bfdd83d11af8bacee8231871ff1292fced")
        self.assertEqual(set(witness.PINNED),
                         {"LICENSE", "services/email_loader_mbox.py"})
        self.assertEqual(witness.BASE.split("/")[2], "raw.githubusercontent.com")
        with self.assertRaisesRegex(witness.WitnessDenied, "SOURCE_PATH_NOT_ALLOWED"):
            witness.fetch("../internal.env")

    def test_distinct_source_occurrences_not_same_as_internet_id(self):
        msgs = witness.messages()
        self.assertEqual(len(msgs), 3)
        self.assertEqual(msgs[0]["Message-ID"], msgs[1]["Message-ID"])
        self.assertNotEqual(msgs[0]["Subject"], msgs[1]["Subject"])
        self.assertIsNone(msgs[2].get("Message-ID"))

    def test_filename_key_collision_is_adversarial(self):
        first = witness.messages()[0]
        filenames = [part.get_filename() for part in first.walk()
                     if part.get_filename()]
        self.assertEqual(filenames, ["report.txt", "report.txt"])
        payloads = [part.get_payload(decode=True) for part in first.walk()
                    if part.get_filename()]
        self.assertEqual(len(set(payloads)), 2)

    def test_git_blob_hash_changes_on_mutation(self):
        a = b"public synthetic control"
        b = a + b"x"
        self.assertNotEqual(witness.git_blob_sha(a), witness.git_blob_sha(b))
        self.assertEqual(len(witness.git_blob_sha(a)), 40)

    def test_fake_store_models_original_unique_id_behavior(self):
        s = witness.FakeSession()
        first = witness.FakeEmail(id="<a@invalid.test>", body="first")
        s.add(first)
        self.assertIs(s.query(witness.FakeEmail).filter_by(id=first.id).first(), first)
        s.add(witness.FakeEmail(id=first.id, body="second"))
        self.assertEqual(len(s.emails), 1)
        self.assertEqual(s.emails[first.id].body, "second")
        s.close()
        self.assertTrue(s.closed)


if __name__ == "__main__":
    unittest.main()
