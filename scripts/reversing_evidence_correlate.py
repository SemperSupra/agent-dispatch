#!/usr/bin/env python3
"""Public-safe synthetic static/dynamic evidence correlator; never executes targets."""
import argparse
import hashlib
import json
import re
from pathlib import Path

INPUT_SCHEMA = "reversing-correlation-input/v1"
RESULT_SCHEMA = "reversing-correlation-result/v1"
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
HASH = re.compile(r"^[a-f0-9]{64}$")
U64 = 2**64 - 1
EVENT_KINDS = {"instruction", "network", "file", "memory", "driver"}
VANTAGES = {"guest", "host", "hypervisor", "emulator"}
MODES = {"stock", "instrumented", "synthetic"}

class ContractError(ValueError):
    pass

def keys(x, mandatory, optional=()):
    if not isinstance(x, dict) or not set(mandatory).issubset(x) or set(x) - set(mandatory) - set(optional):
        raise ContractError("missing or forbidden fields")

def identity(x):
    if not isinstance(x, str) or not ID.fullmatch(x):
        raise ContractError("invalid id")

def digest(x):
    if not isinstance(x, str) or not HASH.fullmatch(x):
        raise ContractError("invalid sha256")

def integer(x, minimum=0):
    if type(x) is not int or not minimum <= x <= U64:
        raise ContractError("invalid uint64")
    return x

def region(start, length):
    integer(start); integer(length, 1)
    if start > U64 - length:
        raise ContractError("address interval overflow")

def validate(doc):
    keys(doc, ("schema", "run_id", "mode", "artifact_sha256", "functions", "module_loads", "events"))
    if doc["schema"] != INPUT_SCHEMA or not isinstance(doc["mode"], str) or doc["mode"] not in MODES:
        raise ContractError("unsupported contract")
    identity(doc["run_id"]); digest(doc["artifact_sha256"])
    for k in ("functions", "module_loads", "events"):
        rows = doc[k]
        if not isinstance(rows, list) or len(rows) > 1024:
            raise ContractError("invalid bounded array")
        seen = set()
        for r in rows:
            if not isinstance(r, dict) or "id" not in r:
                raise ContractError("missing object id")
            identity(r["id"])
            if r["id"] in seen:
                raise ContractError("duplicate id")
            seen.add(r["id"])
    for f in doc["functions"]:
        keys(f, ("id", "rva", "size"))
        region(f["rva"], f["size"])
    for m in doc["module_loads"]:
        keys(m, ("id", "artifact_sha256", "base_va", "size"))
        digest(m["artifact_sha256"])
        region(m["base_va"], m["size"])
    for e in doc["events"]:
        keys(e, ("id", "kind", "sensor", "vantage", "run_id", "time_domain"),
             ("module_load_id", "va", "cause_event_id", "resource_token"))
        for k in ("sensor", "run_id", "time_domain"):
            identity(e[k])
        if (not isinstance(e["kind"], str) or not isinstance(e["vantage"], str)
                or e["kind"] not in EVENT_KINDS or e["vantage"] not in VANTAGES):
            raise ContractError("unsupported event")
        if e["kind"] == "instruction":
            if not {"module_load_id", "va"} <= set(e) or {"cause_event_id", "resource_token"} & set(e):
                raise ContractError("invalid instruction event")
            identity(e["module_load_id"]); integer(e["va"])
        elif {"module_load_id", "va"} & set(e):
            raise ContractError("external sensor cannot self-assign instruction address")
        for k in ("cause_event_id", "resource_token"):
            if k in e:
                identity(e[k])

def correlate(doc):
    validate(doc)
    loads = {x["id"]: x for x in doc["module_loads"]}
    events = {x["id"]: x for x in doc["events"]}
    matches, unknown, external, links, bad_links = [], [], [], [], []
    mapped = {}
    seen = set()
    for e in doc["events"]:
        eid = e["id"]
        if e["run_id"] != doc["run_id"]:
            unknown.append({"event_id": eid, "reason": "FOREIGN_RUN"})
            continue
        if e["kind"] != "instruction":
            external.append({"event_id": eid, "kind": e["kind"],
                             "vantage": e["vantage"], "status": "UNATTRIBUTED"})
            continue
        load = loads.get(e["module_load_id"])
        if load is None:
            reason = "UNKNOWN_LOAD"
        elif load["artifact_sha256"] != doc["artifact_sha256"]:
            reason = "ARTIFACT_MISMATCH"
        elif not load["base_va"] <= e["va"] < load["base_va"] + load["size"]:
            reason = "OUTSIDE_LOAD"
        else:
            reason = None
        if reason:
            unknown.append({"event_id": eid, "reason": reason})
            continue
        rva = e["va"] - load["base_va"]
        choices = sorted(f["id"] for f in doc["functions"]
                         if f["rva"] <= rva < f["rva"] + f["size"])
        if len(choices) != 1:
            unknown.append({"event_id": eid,
                            "reason": "AMBIGUOUS_FUNCTION" if choices else "NO_FUNCTION",
                            "candidate_ids": choices})
            continue
        match = {"event_id": eid, "function_id": choices[0],
                 "load_id": load["id"], "rva": rva,
                 "basis": "EXACT_LOAD_REBASE_AND_UNIQUE_STATIC_INTERVAL",
                 "scope": "OBSERVED_EXECUTION_ADDRESS_ONLY"}
        matches.append(match)
        mapped[eid] = match
        seen.add(choices[0])
    for x in external:
        e = events[x["event_id"]]
        cause_id = e.get("cause_event_id")
        if cause_id is None:
            continue
        cause = events.get(cause_id)
        if cause is None:
            reason = "UNKNOWN_CAUSE"
        elif cause["kind"] != "instruction" or cause["run_id"] != doc["run_id"]:
            reason = "INVALID_CAUSE_CONTEXT"
        elif cause_id not in mapped:
            reason = "UNRESOLVED_CAUSE"
        else:
            reason = None
        if reason:
            bad_links.append({"event_id": e["id"], "cause_event_id": cause_id, "reason": reason})
        else:
            links.append({"event_id": e["id"], "cause_event_id": cause_id,
                          "function_id": mapped[cause_id]["function_id"],
                          "basis": "CALLER_ASSERTED_SAME_RUN_EDGE_UNVERIFIED"})
            x["status"] = "ASSERTED_CAUSE_UNVERIFIED"
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return {
        "schema": RESULT_SCHEMA, "run_id": doc["run_id"], "mode": doc["mode"],
        "artifact_sha256": doc["artifact_sha256"],
        "input_sha256": hashlib.sha256(canonical).hexdigest(),
        "matched_instructions": matches, "unresolved_observations": unknown,
        "external_events": external, "causal_links": links, "unresolved_links": bad_links,
        "static_functions_not_observed": sorted(f["id"] for f in doc["functions"] if f["id"] not in seen),
        "interpretation": {
            "coverage": "OBSERVED_SAMPLES_ONLY_NOT_EXHAUSTIVE",
            "static_not_observed": "NOT_EVIDENCE_OF_UNREACHABILITY",
            "external_events": "NO_CODE_ATTRIBUTION_WITHOUT_EXPLICIT_CAUSE_AND_INDEPENDENT_ORACLE",
            "time_domains": "NOT_SYNCHRONIZED_BY_THIS_ADAPTER",
            "semantic_equivalence": "NOT_PROVEN",
        },
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.input.is_symlink() or not a.input.is_file() or a.input.stat().st_size > 1048576:
        p.error("input must be ordinary file <=1MiB")
    try:
        result = correlate(json.loads(a.input.read_text(encoding="utf-8")))
    except (ValueError, UnicodeError) as exc:
        p.error(str(exc))
    a.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()
