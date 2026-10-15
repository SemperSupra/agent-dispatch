"""Application completion reports are claims, not trusted exit-code evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import takeout_synthetic_fixture as fixture
from takeout_application_completion import (
    NAME, ReceiptBlocked, inventory, publish, validate,
)

SOURCE = "takeout-synthetic-fixture/v1"
OPERATION = "t6-test-fresh-operation-001"


def manifest():
    return {
        name: {"bytes": len(data), "sha256": fixture.sha(data)}
        for name, data in {**fixture.FILES, "retained-sentinel.txt": fixture.SENTINEL}.items()
    }


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.archive, self.state = root / "archive", root / "state"
        self.archive.mkdir()
        self.state.mkdir()

    def run_report(self):
        result = fixture.run(self.archive, self.state, completion_operation=OPERATION)
        self.assertTrue(result["fixture_server_closed"])
        return self.state / NAME

    def accepted(self, *, operation=OPERATION, expected=None):
        return validate(self.state / NAME, self.archive,
                        operation_id=operation, expected=expected or manifest(),
                        expected_source=SOURCE)

    def test_application_report_and_independent_verification(self):
        self.run_report()
        doc = json.loads((self.state / NAME).read_text())
        self.assertEqual(doc["classification"], "APPLICATION_REPORTED_COMPLETE")
        result = self.accepted()
        self.assertEqual(result["verified_count"], 4)
        self.assertFalse(result["process_exit_zero_verified"])
        self.assertFalse(result["app_report_trusted_as_exit_evidence"])
        self.assertFalse(result["guest_qualified"])

    def test_absent_report_never_success(self):
        fixture.run(self.archive, self.state)
        with self.assertRaisesRegex(ReceiptBlocked, "MISSING_OR_UNOWNED_RECEIPT"):
            self.accepted()

    def test_wrong_operation_and_source_rejected(self):
        self.run_report()
        with self.assertRaisesRegex(ReceiptBlocked, "STALE_OR_FOREIGN_OPERATION"):
            self.accepted(operation="t6-test-other-operation-002")
        with self.assertRaisesRegex(ReceiptBlocked, "STALE_OR_FOREIGN_OPERATION"):
            validate(self.state / NAME, self.archive, operation_id=OPERATION,
                     expected=manifest(), expected_source="foreign-source/v1")

    def test_tamper_archive_after_valid_receipt_halts(self):
        self.run_report()
        (self.archive / "part-002.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(ReceiptBlocked, "FILE_BYTES_OR_HASH_MISMATCH"):
            self.accepted()

    def test_extra_file_or_partial_prevents_acceptance(self):
        self.run_report()
        (self.archive / "foreign.part").write_bytes(b"stale")
        with self.assertRaisesRegex(ReceiptBlocked, "ARCHIVE_INVENTORY_MISMATCH"):
            self.accepted()

    def test_valid_but_incomplete_self_report_not_accepted(self):
        self.run_report()
        doc = json.loads((self.state / NAME).read_text())
        doc["files"].pop("part-002.bin")
        (self.state / NAME).write_text(json.dumps(doc))
        with self.assertRaisesRegex(ReceiptBlocked, "RECEIPT_INVENTORY_MISMATCH"):
            self.accepted()

    def test_manifest_substitution_cannot_hide_expected_part(self):
        self.run_report()
        expected = manifest()
        expected.pop("part-003.zip")
        with self.assertRaisesRegex(ReceiptBlocked, "ARCHIVE_INVENTORY_MISMATCH"):
            self.accepted(expected=expected)

    def test_refuse_overwrite_previous_completion(self):
        p = self.run_report()
        before = p.read_bytes()
        with self.assertRaisesRegex(ReceiptBlocked, "PRIOR_RECEIPT_PRESENT"):
            fixture.run(self.archive, self.state, completion_operation="t6-new-operation-002")
        self.assertEqual(p.read_bytes(), before)

    def test_failed_run_never_publishes_report(self):
        fixture.run(self.archive, self.state)
        (self.archive / "part-001.zip").write_bytes(b"corrupt")
        with self.assertRaises(ValueError):
            fixture.run(self.archive, self.state, completion_operation=OPERATION)
        self.assertFalse((self.state / NAME).exists())

    def test_state_must_be_distinct(self):
        with self.assertRaises(ValueError):
            fixture.run(self.archive, self.archive, completion_operation=OPERATION)
        self.assertFalse((self.archive / NAME).exists())

    def test_nonregular_archive_member_rejected(self):
        self.run_report()
        p = self.archive / "part-001.zip"
        p.unlink()
        p.symlink_to(self.archive / "part-002.bin")
        with self.assertRaisesRegex(ReceiptBlocked, "NONREGULAR_FILE"):
            self.accepted()

    def test_independent_verifier_requires_expected_bytes_and_digest(self):
        self.run_report()
        expect = manifest()
        expect["part-002.bin"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ReceiptBlocked, "FILE_BYTES_OR_HASH_MISMATCH"):
            self.accepted(expected=expect)

    def test_report_not_a_process_exit_or_credential(self):
        self.run_report()
        result = self.accepted()
        self.assertNotIn("exit_code", result)
        self.assertNotIn("cookie", (self.state / NAME).read_text().lower())
        self.assertEqual(result["physical_apply"], "HOLD")

    def test_only_host_supplied_fresh_operation_identity(self):
        with self.assertRaisesRegex(ReceiptBlocked, "OPERATION_ID_INVALID"):
            publish(self.state, self.archive, operation_id="../../escape",
                    expected=manifest(), expected_source=SOURCE)

    def test_duplicate_hardlinked_file_is_not_accepted(self):
        self.run_report()
        import os
        p = self.archive / "part-002.bin"
        alias = Path(self.temp.name) / "hardlinked-alias"
        os.link(p, alias)
        with self.assertRaisesRegex(ReceiptBlocked, "NONREGULAR_FILE"):
            self.accepted()


if __name__ == "__main__":
    unittest.main()
