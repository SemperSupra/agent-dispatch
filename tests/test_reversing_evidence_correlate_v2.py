import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("v2", ROOT / "scripts" / "reversing_evidence_correlate_v2.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
H = "a" * 64

def fixture():
    return {
        "schema": M.INPUT, "run_id": "synthetic-run", "mode": "synthetic",
        "artifact_sha256": H,
        "functions": [{"id": "recovered_optimized_function",
                       "intervals": [{"rva": 256, "size": 16}, {"rva": 512, "size": 24}]}],
        "module_loads": [{"id": "mapped", "base_va": 0x500000, "size": 4096, "artifact_sha256": H}],
        "events": [{"id": "entry", "kind": "instruction", "sensor": "gdb", "vantage": "guest",
                    "run_id": "synthetic-run", "time_domain": "debugger",
                    "module_load_id": "mapped", "va": 0x500100},
                   {"id": "second_range", "kind": "instruction", "sensor": "gdb",
                    "vantage": "guest", "run_id": "synthetic-run", "time_domain": "debugger",
                    "module_load_id": "mapped", "va": 0x500205},
                   {"id": "gap", "kind": "instruction", "sensor": "gdb", "vantage": "guest",
                    "run_id": "synthetic-run", "time_domain": "debugger",
                    "module_load_id": "mapped", "va": 0x500180}],
    }

class IntervalSetTests(unittest.TestCase):
    def test_disjoint_ranges_preserve_same_function_identity(self):
        r=M.correlate(fixture())
        self.assertEqual([m["function_id"] for m in r["matched_instructions"]],
                         ["recovered_optimized_function"] * 2)
        self.assertEqual([m["interval_index"] for m in r["matched_instructions"]], [0, 1])
        self.assertEqual(r["unresolved_observations"][0]["event_id"], "gap")
        self.assertEqual(r["unresolved_observations"][0]["reason"], "NO_FUNCTION")
        self.assertFalse(r["static_functions_not_observed"])

    def test_causal_edges_preserve_unverified_status(self):
        x=fixture()
        x["events"].append({"id":"packet","kind":"network","sensor":"vnic",
                            "vantage":"host","run_id":"synthetic-run",
                            "time_domain":"host-clock","cause_event_id":"second_range"})
        r=M.correlate(x)
        self.assertEqual(r["causal_links"][0]["function_id"], "recovered_optimized_function")
        self.assertEqual(r["causal_links"][0]["basis"], "CALLER_ASSERTED_SAME_RUN_EDGE_UNVERIFIED")

    def test_order_independent_range_owners(self):
        x=fixture(); x["functions"][0]["intervals"].reverse()
        r=M.correlate(x)
        self.assertEqual(len(r["matched_instructions"]), 2)
        self.assertNotEqual(r["input_sha256"], M.correlate(fixture())["input_sha256"])

    def test_reject_overlapping_intervals_same_function(self):
        x=fixture(); x["functions"][0]["intervals"][1]["rva"]=264
        with self.assertRaises(M.V1.ContractError): M.correlate(x)

    def test_ambiguous_between_distinct_functions(self):
        x=fixture()
        x["functions"].append({"id":"other","intervals":[{"rva":256,"size":8}]})
        r=M.correlate(x)
        a=next(z for z in r["unresolved_observations"] if z["event_id"]=="entry")
        self.assertEqual(a["reason"], "AMBIGUOUS_FUNCTION")
        self.assertEqual(a["candidate_ids"], ["other", "recovered_optimized_function"])

    def test_reject_unknown_fields_and_absent_ranges(self):
        x=fixture(); x["functions"][0]["raw_binary"]="private"
        with self.assertRaises(M.V1.ContractError): M.correlate(x)
        x=fixture(); x["functions"][0]["intervals"]=[]
        with self.assertRaises(M.V1.ContractError): M.correlate(x)

    def test_reject_duplicate_function_identity(self):
        x=fixture(); x["functions"].append(copy.deepcopy(x["functions"][0]))
        with self.assertRaises(M.V1.ContractError): M.correlate(x)

    def test_reject_wrong_schema_and_uint_overflow(self):
        x=fixture(); x["schema"]="reversing-correlation-input/v1"
        with self.assertRaises(M.V1.ContractError): M.correlate(x)
        x=fixture(); x["functions"][0]["intervals"][1]["rva"]=M.V1.U64
        with self.assertRaises(M.V1.ContractError): M.correlate(x)

    def test_negative_foreign_run_preserved(self):
        x=fixture(); x["events"][0]["run_id"]="foreign"
        r=M.correlate(x)
        self.assertEqual(r["unresolved_observations"][0]["reason"], "FOREIGN_RUN")

    def test_reject_nonscalar_enums_as_typed_contract_errors(self):
        for field in ("mode", "kind", "vantage"):
            with self.subTest(field=field):
                x = fixture()
                if field == "mode":
                    x["mode"] = ["synthetic"]
                else:
                    x["events"][0][field] = ["instruction" if field == "kind" else "guest"]
                with self.assertRaises(M.V1.ContractError):
                    M.correlate(x)

    def test_empty_collection_has_no_false_observations(self):
        x=fixture(); x["events"]=[]
        r=M.correlate(x)
        self.assertEqual(r["static_functions_not_observed"], ["recovered_optimized_function"])

if __name__ == "__main__":
    unittest.main()
