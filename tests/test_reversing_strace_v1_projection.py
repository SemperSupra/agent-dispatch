"""Negative qualification for synthetic strace -> existing v1 external evidence."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / "scripts"
def module(file, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

M = module("reversing_strace_v1_projection.py", "strace_v1_projection")
T = M.TRACE

VALID = "\n".join([
 'openat(AT_FDCWD, "trace-proof-output.bin", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600) = 3',
 'write(3, "trace-proof-v1\\n", 15) = 15',
 'close(3) = 0',
 'exit_group(0) = ?',
 '+++ exited with 0 +++'
])

def fixture():
    return {
        "schema": "strace-fixed-fixture-receipt/v0.1",
        "scope": "synthetic-generated-linux-elf-only",
        "status": "NATIVE_SYSCALL_TRACE_FIXTURE_PASS",
        "source_sha256": hashlib.sha256(T.SOURCE.encode()).hexdigest(),
        "executable_sha256": "a"*64,
        "trace_sha256": "b"*64,
        "output_sha256": hashlib.sha256(T.PAYLOAD).hexdigest(),
        "observed": T.check_trace(VALID),
    }

class ProjectionTests(unittest.TestCase):
    def test_external_file_events_remain_unattributed(self):
        p = M.project(fixture())
        self.assertEqual(p["status"], "SYNTHETIC_SYSCALL_AS_UNATTRIBUTED_FILE_EVENTS_PASS")
        self.assertEqual([x["event_id"] for x in p["external_events"]], ["strace-open","strace-write","strace-close"])
        self.assertTrue(all(x["status"] == "UNATTRIBUTED" for x in p["external_events"]))
        self.assertEqual(p["causal_links"], [])
        self.assertEqual(p["matched_instructions"], [])

    def fail(self, field, value):
        r = fixture()
        r[field] = value
        with self.assertRaises(ValueError):
            M.project(r)

    def test_bad_receipt_schema(self):
        self.fail("schema","incorrect")

    def test_unqualified_status(self):
        self.fail("status","SYNTHETIC_CONTRACT_PASS")

    def test_wrong_scope(self):
        self.fail("scope","arbitrary-binaries")

    def test_missing_executable_digest(self):
        self.fail("executable_sha256","bad")

    def test_false_embedded_fixture_hash(self):
        self.fail("source_sha256","f"*64)

    def test_false_output_payload_digest(self):
        self.fail("output_sha256","c"*64)

    def test_unbounded_witness_count(self):
        a = fixture()
        a["observed"]["witness_lines"].append("ignored extra line")
        with self.assertRaises(ValueError):
            M.project(a)

    def test_forged_written_byte_count(self):
        a = fixture()
        a["observed"]["wrote_bytes"]=14
        with self.assertRaises(ValueError):
            M.project(a)

    def test_changed_pid_in_one_witness(self):
        a = fixture()
        a["observed"]["witness_lines"][1]="[pid  1234] "+a["observed"]["witness_lines"][1]
        with self.assertRaises(T.OracleError):
            M.project(a)

    def test_fake_native_completion(self):
        a = fixture()
        a["observed"]["witness_lines"][-1]="+++ exited with 1 +++"
        with self.assertRaises(T.OracleError):
            M.project(a)

if __name__ == "__main__":
    unittest.main()
