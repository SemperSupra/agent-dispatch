#!/usr/bin/env python3
"""Function interval-set v2 adapter over the already-qualified v1 reducer.

No tool execution. Ghidra can represent one optimized function by multiple
disjoint address ranges. Never combine those ranges into a convex hull.
"""
import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "reversing_v1", Path(__file__).with_name("reversing_evidence_correlate.py"))
V1 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V1)
INPUT = "reversing-correlation-input/v2"
OUTPUT = "reversing-correlation-result/v2"


def validate_and_project(doc):
    V1.keys(doc, ("schema", "run_id", "mode", "artifact_sha256", "functions", "module_loads", "events"))
    if doc["schema"] != INPUT:
        raise V1.ContractError("unsupported v2 schema")
    functions = doc["functions"]
    if not isinstance(functions, list) or len(functions) > 1024:
        raise V1.ContractError("unbounded function collection")
    seen = set()
    projected, surrogate_to_original, members = [], {}, {}
    for f in functions:
        V1.keys(f, ("id", "intervals"))
        V1.identity(f["id"])
        if f["id"] in seen:
            raise V1.ContractError("duplicate function identity")
        seen.add(f["id"])
        intervals = f["intervals"]
        if not isinstance(intervals, list) or not 1 <= len(intervals) <= 32:
            raise V1.ContractError("empty/unbounded function interval set")
        pairs = []
        for i, interval in enumerate(intervals):
            V1.keys(interval, ("rva", "size"))
            start, length = interval["rva"], interval["size"]
            V1.region(start, length)
            pairs.append((start, start + length))
            surrogate = "f" + str(len(projected))
            projected.append({"id": surrogate, "rva": start, "size": length})
            surrogate_to_original[surrogate] = (f["id"], i)
            if len(projected) > 1024:
                raise V1.ContractError("unbounded total function intervals")
        ordered = sorted(pairs)
        if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
            raise V1.ContractError("overlap within same function would double count instructions")
        members[f["id"]] = len(intervals)
    legacy = {
        "schema": V1.INPUT_SCHEMA, "run_id": doc["run_id"],
        "mode": doc["mode"], "artifact_sha256": doc["artifact_sha256"],
        "module_loads": doc["module_loads"], "events": doc["events"],
        "functions": projected,
    }
    try:
        V1.validate(legacy)
    except TypeError as exc:
        # v1 membership checks can raise TypeError on JSON arrays/objects
        # supplied where an enum string is required. Reject as contract data.
        raise V1.ContractError("non-scalar projected contract field") from exc
    return legacy, surrogate_to_original, members


def correlate(doc):
    legacy, owner, members = validate_and_project(doc)
    result = V1.correlate(legacy)
    for match in result["matched_instructions"]:
        old = match["function_id"]
        match["function_id"], match["interval_index"] = owner[old]
        match["basis"] = "EXACT_LOAD_REBASE_AND_UNIQUE_DISJOINT_FUNCTION_INTERVAL"
    for candidate in result["unresolved_observations"]:
        if "candidate_ids" in candidate:
            candidate["candidate_ids"] = sorted({
                owner[s][0] for s in candidate["candidate_ids"]})
    for edge in result["causal_links"]:
        edge["function_id"] = owner[edge["function_id"]][0]
    result["static_functions_not_observed"] = sorted(
        fid for fid in members
        if fid not in {m["function_id"] for m in result["matched_instructions"]})
    result["schema"] = OUTPUT
    result["interval_counts"] = [{"function_id": fid, "count": members[fid]}
                                 for fid in sorted(members)]
    result["legacy_projection_sha256"] = result["input_sha256"]
    try:
        canonical = json.dumps(doc, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError, OverflowError) as exc:
        raise V1.ContractError("noncanonical interval-set evidence") from exc
    result["input_sha256"] = sha256(canonical).hexdigest()
    result["interpretation"]["function_identity"] = (
        "ALL_DISJOINT_RANGES_BELONG_TO_ONE_STATIC_FUNCTION")
    result["interpretation"]["gaps"] = (
        "GAPS_NOT_INFERRED_AS_PART_OF_FUNCTION")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.input.is_symlink() or not args.input.is_file() or args.input.stat().st_size > 1048576:
        p.error("ordinary <=1MiB input required")
    try:
        result = correlate(V1.strict_loads(args.input.read_text(encoding="utf-8")))
    except (ValueError, UnicodeError) as exc:
        p.error(str(exc))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
