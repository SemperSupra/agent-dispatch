"""Adversarial, source-known reversing evidence seam properties.

This intentionally does not authenticate runtime telemetry. It verifies that
structural correlation does not silently become causal/semantic authority.
No binary, secret, repository credential, Ghidra download, or network call.
"""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "public_redblue_v2", ROOT / "scripts/reversing_evidence_correlate_v2.py"
)
CORR = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(CORR)

HASH = "a" * 64
RUN = "synthetic-only-redblue"
BASE = 0x400000


def sample():
    # A owns [0x100,0x110) and [0x200,0x208); B overlaps A at
    # [0x108,0x110). No total-order function preference is justified.
    positions = (0xFF, 0x100, 0x107, 0x108, 0x10F, 0x110,
                 0x1FF, 0x200, 0x207, 0x208)
    return {
        "schema": CORR.INPUT, "run_id": RUN, "mode": "synthetic",
        "artifact_sha256": HASH,
        "functions": [
            {"id": "A", "intervals": [
                {"rva": 0x100, "size": 0x10},
                {"rva": 0x200, "size": 0x8},
            ]},
            {"id": "B", "intervals": [
                {"rva": 0x108, "size": 0x8},
            ]},
        ],
        "module_loads": [{
            "id": "load", "artifact_sha256": HASH,
            "base_va": BASE, "size": 0x1000,
        }],
        "events": [{
            "id": f"pc-{rva:x}", "kind": "instruction",
            "sensor": "synthetic-alleged-pc", "vantage": "guest",
            "run_id": RUN, "time_domain": "fictional-run-clock",
            "module_load_id": "load", "va": BASE + rva,
        } for rva in positions],
    }


def ownership(result):
    matches = {event["event_id"]: event["function_id"]
               for event in result["matched_instructions"]}
    rejected = {event["event_id"]: event["reason"]
                for event in result["unresolved_observations"]}
    return matches, rejected


class GeometryProperties(unittest.TestCase):
    def test_half_open_gap_overlap_and_endpoints(self):
        got = CORR.correlate(sample())
        matches, unknown = ownership(got)
        self.assertEqual(matches, {
            "pc-100": "A", "pc-107": "A",
            "pc-200": "A", "pc-207": "A",
        })
        self.assertEqual(unknown, {
            "pc-ff": "NO_FUNCTION", "pc-108": "AMBIGUOUS_FUNCTION",
            "pc-10f": "AMBIGUOUS_FUNCTION", "pc-110": "NO_FUNCTION",
            "pc-1ff": "NO_FUNCTION", "pc-208": "NO_FUNCTION",
        })
        self.assertEqual(got["static_functions_not_observed"], ["B"])
        self.assertEqual(next(x["candidate_ids"]
                              for x in got["unresolved_observations"]
                              if x["event_id"] == "pc-108"), ["A", "B"])

    def test_loader_rebase_preserves_ownership_not_input_digest(self):
        first = sample()
        rebased = copy.deepcopy(first)
        delta = 0x110000
        rebased["module_loads"][0]["base_va"] += delta
        for event in rebased["events"]:
            event["va"] += delta
        one, two = CORR.correlate(first), CORR.correlate(rebased)
        self.assertEqual(ownership(one), ownership(two))
        self.assertNotEqual(one["input_sha256"], two["input_sha256"])
        self.assertEqual([x["rva"] for x in one["matched_instructions"]],
                         [x["rva"] for x in two["matched_instructions"]])

    def test_static_function_input_order_is_not_tiebreaker(self):
        first = sample()
        reordered = copy.deepcopy(first)
        reordered["functions"].reverse()
        one, two = CORR.correlate(first), CORR.correlate(reordered)
        self.assertEqual(ownership(one), ownership(two))
        self.assertNotEqual(one["input_sha256"], two["input_sha256"])

    def test_excessive_fragment_count_is_rejected_not_hulled(self):
        fixture = sample()
        fixture["functions"][0]["intervals"] = [
            {"rva": i * 2, "size": 1} for i in range(33)
        ]
        with self.assertRaises(CORR.V1.ContractError):
            CORR.correlate(fixture)

    def test_foreign_execution_and_load_digest_never_match(self):
        fixture = sample()
        fixture["events"][1]["run_id"] = "foreign-run"
        result = CORR.correlate(fixture)
        _, unknown = ownership(result)
        self.assertEqual(unknown["pc-100"], "FOREIGN_RUN")
        fixture = sample()
        fixture["module_loads"][0]["artifact_sha256"] = "b" * 64
        result = CORR.correlate(fixture)
        matches, unknown = ownership(result)
        self.assertFalse(matches)
        self.assertEqual(set(unknown.values()), {"ARTIFACT_MISMATCH"})


class ProvenanceProperties(unittest.TestCase):
    def test_wellformed_claimed_pc_does_not_authenticate_runtime(self):
        fixture = sample()
        # No real debugger, process, binary or validated witness exists here.
        fixture["events"] = [fixture["events"][1]]
        fixture["events"][0]["sensor"] = "unverified-reporter"
        fixture["events"][0]["vantage"] = "hypervisor"
        result = CORR.correlate(fixture)
        self.assertEqual(len(result["matched_instructions"]), 1)
        evidence = result["matched_instructions"][0]
        self.assertEqual(evidence["scope"], "OBSERVED_EXECUTION_ADDRESS_ONLY")
        self.assertEqual(evidence["basis"],
                         "EXACT_LOAD_REBASE_AND_UNIQUE_DISJOINT_FUNCTION_INTERVAL")
        self.assertEqual(result["interpretation"]["semantic_equivalence"],
                         "NOT_PROVEN")
        self.assertNotIn("authenticated", evidence)
        self.assertNotIn("execution_attested", result)

    def test_external_event_is_unattributed_even_with_asserted_cause(self):
        fixture = sample()
        fixture["events"] = [fixture["events"][1]]
        fixture["events"].append({
            "id": "file-write", "kind": "file", "sensor": "strace",
            "vantage": "host", "run_id": RUN, "time_domain": "host-time",
            "cause_event_id": "pc-100", "resource_token": "synthetic-file",
        })
        result = CORR.correlate(fixture)
        self.assertEqual(result["matched_instructions"][0]["function_id"], "A")
        self.assertEqual(result["external_events"][0]["status"],
                         "ASSERTED_CAUSE_UNVERIFIED")
        self.assertEqual(result["causal_links"][0]["basis"],
                         "CALLER_ASSERTED_SAME_RUN_EDGE_UNVERIFIED")
        self.assertEqual(result["interpretation"]["time_domains"],
                         "NOT_SYNCHRONIZED_BY_THIS_ADAPTER")

    def test_cross_run_causal_assertion_is_not_accepted(self):
        fixture = sample()
        fixture["events"] = [fixture["events"][1]]
        fixture["events"][0]["run_id"] = "other-run"
        fixture["events"].append({
            "id": "file-write", "kind": "file", "sensor": "strace",
            "vantage": "host", "run_id": RUN, "time_domain": "host-time",
            "cause_event_id": "pc-100",
        })
        result = CORR.correlate(fixture)
        self.assertFalse(result["causal_links"])
        self.assertEqual(result["unresolved_links"][0]["reason"],
                         "INVALID_CAUSE_CONTEXT")

    def test_duplicate_and_nonfinite_input_refused_before_projection(self):
        valid = json.dumps(sample(), sort_keys=True)
        self.assertEqual(CORR.correlate(CORR.V1.strict_loads(valid)),
                         CORR.correlate(sample()))
        malformed = (
            valid.replace('"base_va": 4194304',
                          '"base_va": 0, "base_va": 4194304', 1),
            valid.replace('"mode": "synthetic"', '"mode": Infinity', 1),
        )
        self.assertNotEqual(malformed[0], valid)
        self.assertNotEqual(malformed[1], valid)
        for raw in malformed:
            with self.subTest(raw=raw[:80]):
                with self.assertRaises(CORR.V1.ContractError):
                    CORR.V1.strict_loads(raw)

    def test_untrusted_claim_cannot_promote_semantic_equivalence(self):
        fixture = sample()
        fixture["events"] = [fixture["events"][1]]
        result = CORR.correlate(fixture)
        self.assertNotEqual(result["interpretation"]["semantic_equivalence"],
                            "PROVEN")
        self.assertIn("NOT_EXHAUSTIVE", result["interpretation"]["coverage"])


if __name__ == "__main__":
    unittest.main()
