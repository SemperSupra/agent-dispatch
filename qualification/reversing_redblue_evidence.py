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


class BatchProperties(unittest.TestCase):
    """Single batch reuses bounded fixtures to test many adversarial cases."""

    def test_forty_aslr_and_event_order_permutations(self):
        baseline = sample()
        expected = ownership(CORR.correlate(baseline))
        for iteration in range(40):
            with self.subTest(iteration=iteration):
                probe = copy.deepcopy(baseline)
                delta = (iteration + 1) * 0x10000
                probe["module_loads"][0]["base_va"] += delta
                for event in probe["events"]:
                    event["va"] += delta
                if iteration % 2:
                    probe["functions"].reverse()
                    probe["events"].reverse()
                actual = CORR.correlate(probe)
                self.assertEqual(ownership(actual), expected)
                self.assertEqual(len(actual["matched_instructions"]), 4)
                self.assertEqual(len(actual["unresolved_observations"]), 6)
                self.assertNotEqual(actual["input_sha256"],
                                    CORR.correlate(baseline)["input_sha256"])

    def test_twenty_address_boundary_oracle(self):
        x = sample()
        x["functions"] = [
            {"id": "A", "intervals": [{"rva": 8, "size": 4}]},
            {"id": "B", "intervals": [{"rva": 10, "size": 4}]},
        ]
        x["events"] = [
            {"id": f"r-{i}", "kind": "instruction", "sensor": "bounded",
             "vantage": "guest", "run_id": RUN, "time_domain": "synthetic",
             "module_load_id": "load", "va": BASE + i}
            for i in range(20)
        ]
        yes, no = ownership(CORR.correlate(x))
        self.assertEqual(yes, {"r-8": "A", "r-9": "A",
                               "r-12": "B", "r-13": "B"})
        self.assertEqual(no, {
            f"r-{i}": ("AMBIGUOUS_FUNCTION" if 10 <= i < 12 else "NO_FUNCTION")
            for i in range(20) if i not in (8, 9, 12, 13)
        })

    def test_nested_duplicate_member_mutation_batch(self):
        valid = json.dumps(sample(), sort_keys=True)
        edits = (
            ('"id": "A"', '"id": "forged", "id": "A"'),
            ('"rva": 256', '"rva": 999, "rva": 256'),
            ('"module_load_id": "load"',
             '"module_load_id": "missing", "module_load_id": "load"'),
            ('"time_domain": "fictional-run-clock"',
             '"time_domain": "forged", "time_domain": "fictional-run-clock"'),
        )
        for original, mutation in edits:
            with self.subTest(member=original):
                self.assertIn(original, valid)
                with self.assertRaises(CORR.V1.ContractError):
                    CORR.V1.strict_loads(valid.replace(original, mutation, 1))

    def test_event_array_budget_1024_accepted_1025_refused(self):
        x = sample()
        template = copy.deepcopy(x["events"][1])
        x["events"] = [{**template, "id": f"sample-{i}"} for i in range(1024)]
        output = CORR.correlate(x)
        self.assertEqual(len(output["matched_instructions"]), 1024)
        self.assertEqual({v["function_id"] for v in output["matched_instructions"]},
                         {"A"})
        x["events"].append({**template, "id": "sample-1024"})
        with self.assertRaises(CORR.V1.ContractError):
            CORR.correlate(x)

    def test_overflow_and_same_function_overlap_rejected(self):
        x = sample()
        x["functions"][0]["intervals"][1]["rva"] = 0x107
        with self.assertRaises(CORR.V1.ContractError):
            CORR.correlate(x)
        x = sample()
        x["functions"][0]["intervals"][0]["rva"] = CORR.V1.U64
        with self.assertRaises(CORR.V1.ContractError):
            CORR.correlate(x)
        x = sample()
        x["module_loads"][0]["base_va"] = CORR.V1.U64
        with self.assertRaises(CORR.V1.ContractError):
            CORR.correlate(x)

    def test_unknown_or_unresolved_cause_never_creates_edge(self):
        x = sample()
        x["events"] = [x["events"][0], {
            "id": "file", "kind": "file", "sensor": "strace",
            "vantage": "host", "run_id": RUN, "time_domain": "host",
            "cause_event_id": "absent",
        }]
        r = CORR.correlate(x)
        self.assertFalse(r["causal_links"])
        self.assertEqual(r["unresolved_links"][0]["reason"], "UNKNOWN_CAUSE")
        x["events"][1]["cause_event_id"] = "pc-ff"
        r = CORR.correlate(x)
        self.assertFalse(r["causal_links"])
        self.assertEqual(r["unresolved_links"][0]["reason"], "UNRESOLVED_CAUSE")

    def test_foreign_external_does_not_gain_cross_run_link(self):
        x = sample()
        x["events"] = [x["events"][1], {
            "id": "foreign-file", "kind": "file", "sensor": "strace",
            "vantage": "host", "run_id": "different-run",
            "time_domain": "host", "cause_event_id": "pc-100",
        }]
        r = CORR.correlate(x)
        self.assertFalse(r["external_events"])
        self.assertFalse(r["causal_links"])
        self.assertEqual(r["unresolved_observations"][0]["reason"], "FOREIGN_RUN")


class DifferentialReferenceProperties(unittest.TestCase):
    """Independent byte-set truth, not a second copy of v2's projection."""

    def test_sixteen_seed_byte_level_oracle_4096_observations(self):
        import random
        for seed in range(16):
            with self.subTest(seed=seed):
                rng = random.Random(0xD1FF + seed)
                functions = [
                    {"id": f"F{i}", "intervals": [
                        {"rva": 8 + j * 80 + ((i * 17 + seed * 11 + j * 3) % 36),
                         "size": 1 + ((seed + i + j) % 13)}
                        for j in range(3)]}
                    for i in range(8)
                ]
                # Ranges within one function are disjoint by construction;
                # overlaps across functions are intentionally possible.
                events = [
                    {"id": f"byte-{rva}", "kind": "instruction",
                     "sensor": "independent-byte-oracle", "vantage": "guest",
                     "run_id": RUN, "time_domain": "synthetic-reference",
                     "module_load_id": "load", "va": BASE + rva}
                    for rva in range(256)
                ]
                rng.shuffle(functions)
                rng.shuffle(events)
                x = sample()
                x["functions"], x["events"] = functions, events
                actual = CORR.correlate(x)
                matches = {m["event_id"]: m for m in actual["matched_instructions"]}
                unresolved = {u["event_id"]: u for u in actual["unresolved_observations"]}
                self.assertEqual(len(matches) + len(unresolved), 256)
                unique_owners = set()
                for rva in range(256):
                    eid = f"byte-{rva}"
                    owners = [
                        fun["id"] for fun in functions
                        if any(interval["rva"] <= rva <
                               interval["rva"] + interval["size"]
                               for interval in fun["intervals"])
                    ]
                    if len(owners) == 1:
                        unique_owners.add(owners[0])
                        self.assertEqual(matches[eid]["function_id"], owners[0])
                        self.assertEqual(matches[eid]["rva"], rva)
                        self.assertNotIn(eid, unresolved)
                        function = next(f for f in functions if f["id"] == owners[0])
                        indices = [idx for idx, interval in enumerate(function["intervals"])
                                   if interval["rva"] <= rva <
                                   interval["rva"] + interval["size"]]
                        self.assertEqual(indices, [matches[eid]["interval_index"]])
                    else:
                        self.assertNotIn(eid, matches)
                        self.assertEqual(
                            unresolved[eid]["reason"],
                            "AMBIGUOUS_FUNCTION" if owners else "NO_FUNCTION")
                        self.assertEqual(unresolved[eid]["candidate_ids"],
                                         sorted(owners))
                self.assertEqual(actual["static_functions_not_observed"],
                                 sorted(set(f["id"] for f in functions) - unique_owners))
                self.assertEqual(actual["interpretation"]["semantic_equivalence"],
                                 "NOT_PROVEN")

    def test_cross_module_load_hash_does_not_leak_identity(self):
        x = sample()
        x["events"] = [copy.deepcopy(x["events"][1])]
        x["module_loads"].append({
            "id": "wrong-image-same-address",
            "artifact_sha256": "b" * 64,
            "base_va": BASE, "size": 0x1000,
        })
        x["events"].append({
            **copy.deepcopy(x["events"][0]),
            "id": "wrong-image-pc",
            "module_load_id": "wrong-image-same-address",
            "va": BASE + 0x100,
        })
        got = CORR.correlate(x)
        self.assertEqual([m["event_id"] for m in got["matched_instructions"]],
                         ["pc-100"])
        self.assertEqual(got["unresolved_observations"][0],
                         {"event_id": "wrong-image-pc",
                          "reason": "ARTIFACT_MISMATCH"})

    def test_json_exponent_overflow_never_becomes_accepted_evidence(self):
        raw = json.dumps(sample(), sort_keys=True)
        mutated = raw.replace('"base_va": 4194304',
                              '"base_va": 1e309', 1)
        self.assertNotEqual(raw, mutated)
        try:
            decoded = CORR.V1.strict_loads(mutated)
        except CORR.V1.ContractError:
            pass  # A stricter parser is acceptable.
        else:
            with self.assertRaises(CORR.V1.ContractError):
                CORR.correlate(decoded)

    def test_json_escaped_duplicate_key_is_rejected(self):
        raw = json.dumps(sample(), sort_keys=True)
        self.assertIn('"id": "A"', raw)
        duplicate = raw.replace('"id": "A"',
                                r'"\u0069d": "forged", "id": "A"', 1)
        with self.assertRaises(CORR.V1.ContractError):
            CORR.V1.strict_loads(duplicate)


if __name__ == "__main__":
    unittest.main()
