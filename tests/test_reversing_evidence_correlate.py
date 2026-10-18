import copy
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "reversing_evidence_correlate.py"
SPEC = importlib.util.spec_from_file_location("reversing_evidence_correlate", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
H, B = "a" * 64, "b" * 64

def fixture():
    return {
        "schema": MOD.INPUT_SCHEMA, "run_id": "test-run", "mode": "synthetic", "artifact_sha256": H,
        "functions": [{"id": "first", "rva": 0x100, "size": 0x20},
                      {"id": "second", "rva": 0x140, "size": 0x10},
                      {"id": "unused", "rva": 0x300, "size": 0x10}],
        "module_loads": [{"id": "load-1", "artifact_sha256": H,
                          "base_va": 0x70000000, "size": 0x1000}],
        "events": [{"id": "i1", "kind": "instruction", "sensor": "gdb",
                    "vantage": "guest", "run_id": "test-run", "time_domain": "guest-mono",
                    "module_load_id": "load-1", "va": 0x70000105}],
    }

def external(cause=None):
    e = {"id": "x1", "kind": "network", "vantage": "hypervisor", "sensor": "observer",
         "run_id": "test-run", "time_domain": "host-mono"}
    if cause is not None:
        e["cause_event_id"] = cause
    return e

class CorrelationTests(unittest.TestCase):
    def test_rebase_and_unobserved_not_unreachable(self):
        r = MOD.correlate(fixture())
        self.assertEqual(r["matched_instructions"][0]["rva"], 0x105)
        self.assertEqual(r["matched_instructions"][0]["function_id"], "first")
        self.assertEqual(r["static_functions_not_observed"], ["second", "unused"])
        self.assertEqual(r["interpretation"]["static_not_observed"], "NOT_EVIDENCE_OF_UNREACHABILITY")

    def test_distinct_load_mapping(self):
        x = fixture()
        x["module_loads"].append({"id": "load-2", "artifact_sha256": H,
                                  "base_va": 0x40000000, "size": 0x1000})
        x["events"][0].update(module_load_id="load-2", va=0x40000146)
        self.assertEqual(MOD.correlate(x)["matched_instructions"][0]["function_id"], "second")

    def test_half_open_range(self):
        x = fixture(); x["events"][0]["va"] = 0x70000120
        self.assertEqual(MOD.correlate(x)["unresolved_observations"][0]["reason"], "NO_FUNCTION")

    def test_ambiguous_overlap_is_not_guessed(self):
        x = fixture(); x["functions"].append({"id": "overlap", "rva": 0x104, "size": 0x10})
        r = MOD.correlate(x)
        self.assertFalse(r["matched_instructions"])
        self.assertEqual(r["unresolved_observations"][0]["reason"], "AMBIGUOUS_FUNCTION")

    def test_unknown_load(self):
        x = fixture(); x["events"][0]["module_load_id"] = "not-loaded"
        self.assertEqual(MOD.correlate(x)["unresolved_observations"][0]["reason"], "UNKNOWN_LOAD")

    def test_artifact_mismatch(self):
        x = fixture(); x["module_loads"][0]["artifact_sha256"] = B
        self.assertEqual(MOD.correlate(x)["unresolved_observations"][0]["reason"], "ARTIFACT_MISMATCH")

    def test_address_outside_load(self):
        x = fixture(); x["events"][0]["va"] = 0x80001000
        self.assertEqual(MOD.correlate(x)["unresolved_observations"][0]["reason"], "OUTSIDE_LOAD")

    def test_external_cannot_infer_cause_from_time(self):
        x = fixture(); x["events"].append(external())
        r = MOD.correlate(x)
        self.assertEqual(r["external_events"][0]["status"], "UNATTRIBUTED")
        self.assertFalse(r["causal_links"])

    def test_explicit_cause_can_link(self):
        x = fixture(); x["events"].append(external(cause="i1"))
        r = MOD.correlate(x)
        self.assertEqual(r["causal_links"][0]["function_id"], "first")
        self.assertEqual(r["external_events"][0]["status"], "EXPLICITLY_LINKED")

    def test_foreign_run_excluded_from_causal_join(self):
        x = fixture(); x["events"][0]["run_id"] = "foreign"
        x["events"].append(external(cause="i1"))
        r = MOD.correlate(x)
        self.assertEqual(r["unresolved_observations"][0]["reason"], "FOREIGN_RUN")
        self.assertEqual(r["unresolved_links"][0]["reason"], "INVALID_CAUSE_CONTEXT")

    def test_unresolved_cause_does_not_get_attributed(self):
        x = fixture(); x["events"][0]["va"] = 0x70000200
        x["events"].append(external(cause="i1"))
        self.assertEqual(MOD.correlate(x)["unresolved_links"][0]["reason"], "UNRESOLVED_CAUSE")

    def test_unknown_cause(self):
        x = fixture(); x["events"].append(external(cause="missing"))
        self.assertEqual(MOD.correlate(x)["unresolved_links"][0]["reason"], "UNKNOWN_CAUSE")

    def test_extra_raw_payload_denied(self):
        x = fixture(); x["events"][0]["raw_memory"] = "private"
        with self.assertRaises(MOD.ContractError): MOD.correlate(x)

    def test_integer_overflow_and_bool_denied(self):
        x = fixture(); x["module_loads"][0]["base_va"] = MOD.U64
        with self.assertRaises(MOD.ContractError): MOD.correlate(x)
        x = fixture(); x["events"][0]["va"] = True
        with self.assertRaises(MOD.ContractError): MOD.correlate(x)

    def test_duplicate_ids_and_unknown_type(self):
        x = fixture(); x["events"].append(copy.deepcopy(x["events"][0]))
        with self.assertRaises(MOD.ContractError): MOD.correlate(x)
        x = fixture(); x["events"][0]["kind"] = "shell"
        with self.assertRaises(MOD.ContractError): MOD.correlate(x)

    def test_digest_is_deterministic(self):
        x = fixture()
        self.assertEqual(MOD.correlate(x), MOD.correlate(copy.deepcopy(x)))

if __name__ == "__main__":
    unittest.main()
