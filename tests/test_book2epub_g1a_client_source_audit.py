#!/usr/bin/env python3
"""B1 exact-upstream-source control: all negative probes are source-only."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "scripts" / "book2epub_g1a_client_source_audit.py"
spec = importlib.util.spec_from_file_location("client_source_audit", path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class TaggedSourceAuditTests(unittest.TestCase):
    def test_unpinned_fixture_fails_closed(self):
        raw = b"class Client: pass\n"
        self.assertNotEqual(audit.git_blob_sha(raw), audit.CLIENT_BLOB)
        with self.assertRaisesRegex(audit.AuditError, "exact_upstream_blob_mismatch"):
            audit.audit_bytes(raw)

    def test_empty_or_oversize_refused(self):
        for raw in (b"", b"x" * 100001):
            with self.subTest(length=len(raw)), self.assertRaises(audit.AuditError):
                audit.audit_bytes(raw)

    def test_git_blob_envelope_not_ordinary_data_sha(self):
        import hashlib
        raw = b"hello\n"
        self.assertNotEqual(audit.git_blob_sha(raw), hashlib.sha1(raw).hexdigest())
        self.assertEqual(audit.git_blob_sha(raw), hashlib.sha1(b"blob 6\0hello\n").hexdigest())

    def test_requires_immutably_pinned_upstream_commit_and_blob(self):
        self.assertEqual(len(audit.TAG_COMMIT), 40)
        self.assertEqual(len(audit.CLIENT_BLOB), 40)
        self.assertNotEqual(audit.TAG_COMMIT, audit.CLIENT_BLOB)

    def test_source_audit_cannot_grant_runtime_authority(self):
        # Exact upstream source must be supplied by the separately pinned checkout.
        raw = b"class Client: pass"
        with self.assertRaises(audit.AuditError):
            audit.audit_bytes(raw)


if __name__ == "__main__":
    unittest.main()
