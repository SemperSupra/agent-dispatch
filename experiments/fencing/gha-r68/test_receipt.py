import copy
import unittest
from receipt import ReceiptError, verify

VALID = {
    "id": 41,
    "run_attempt": 2,
    "workflow_id": 99,
    "head_sha": "a" * 40,
    "repository": {"full_name": "SemperSupra/agent-dispatch"},
    "event": "pull_request",
    "status": "in_progress",
    "conclusion": None,
}

class NativeReceiptContract(unittest.TestCase):
    def test_matching_authenticated_readback_is_correlation_only(self):
        v = verify(VALID, "SemperSupra/agent-dispatch", 41, 2, "pull_request")
        self.assertEqual(v["receipt_class"], "CORRELATION_ONLY")
        self.assertEqual(v["external_effect_commit"], "NOT_PROVEN")
        self.assertEqual(v["lost_ack_exactly_once"], "NOT_PROVEN")

    def reject(self, change, expected):
        v = copy.deepcopy(VALID)
        change(v)
        with self.assertRaisesRegex(ReceiptError, expected):
            verify(v, "SemperSupra/agent-dispatch", 41, 2, "pull_request")

    def test_wrong_run_id(self):
        self.reject(lambda v: v.update(id=42), "RUN_ID_MISMATCH")

    def test_wrong_attempt(self):
        self.reject(lambda v: v.update(run_attempt=1), "ATTEMPT_MISMATCH")

    def test_wrong_repository(self):
        self.reject(lambda v: v["repository"].update(full_name="other/secret"), "REPOSITORY_MISMATCH")

    def test_wrong_event(self):
        self.reject(lambda v: v.update(event="workflow_dispatch"), "EVENT_MISMATCH")

    def test_missing_workflow(self):
        self.reject(lambda v: v.update(workflow_id=0), "WORKFLOW_ID_MISSING")

    def test_invalid_head(self):
        self.reject(lambda v: v.update(head_sha="b" * 39), "HEAD_SHA_INVALID")

    def test_unknown_native_state(self):
        self.reject(lambda v: v.update(status="definitely_done"), "STATUS_UNKNOWN")

    def test_id_cannot_be_bool(self):
        self.reject(lambda v: v.update(id=True), "RUN_ID_MISMATCH")

if __name__ == "__main__":
    unittest.main()
