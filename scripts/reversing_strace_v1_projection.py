#!/usr/bin/env python3
"""Adapt one verified fixed synthetic strace receipt to existing v1 external evidence.

This is a projection, NOT a new canonical schema or an instruction-address
correlator. The projected file events remain UNATTRIBUTED.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

TRACE = load_module("reversing_strace_fixture_probe.py", "strace_fixed_fixture")
CORR = load_module("reversing_evidence_correlate.py", "reversing_correlation_v1")
HASH = re.compile(r"[a-f0-9]{64}\Z")


def project(receipt):
    if not isinstance(receipt, dict) or receipt.get("schema") != "strace-fixed-fixture-receipt/v0.1":
        raise ValueError("unsupported native trace receipt")
    if receipt.get("scope") != "synthetic-generated-linux-elf-only" or receipt.get("status") != "NATIVE_SYSCALL_TRACE_FIXTURE_PASS":
        raise ValueError("unqualified or wrong-scope sensor receipt")
    for key in ("source_sha256", "executable_sha256", "trace_sha256", "output_sha256"):
        x = receipt.get(key)
        if not isinstance(x, str) or not HASH.fullmatch(x):
            raise ValueError("invalid receipt digest: " + key)
    if receipt["source_sha256"] != hashlib.sha256(TRACE.SOURCE.encode()).hexdigest():
        raise ValueError("source fixture hash mismatches embedded source")
    if receipt["output_sha256"] != hashlib.sha256(TRACE.PAYLOAD).hexdigest():
        raise ValueError("output digest does not match independent fixture oracle")
    obs = receipt.get("observed")
    if not isinstance(obs, dict) or not isinstance(obs.get("witness_lines"), list) or len(obs["witness_lines"]) != 5 or not all(isinstance(s, str) for s in obs["witness_lines"]):
        raise ValueError("missing bounded five-line native witness")
    verified = TRACE.check_trace("\n".join(obs["witness_lines"]))
    if verified != obs:
        raise ValueError("native witness claims do not agree with re-parsed lines")

    run_id = "fixture-trace-" + receipt["trace_sha256"][:24]
    base = {
        "schema": CORR.INPUT_SCHEMA, "run_id": run_id,
        "mode": "synthetic", "artifact_sha256": receipt["executable_sha256"],
        "functions": [], "module_loads": [], "events": []
    }
    for kind in ("open", "write", "close"):
        base["events"].append({
            "id": "strace-" + kind, "kind": "file", "sensor": "strace-linux",
            "vantage": "guest", "run_id": run_id, "time_domain": "syscall-sequence",
            "resource_token": "known-fixture-file"
        })
    result = CORR.correlate(base)
    if (len(result["external_events"]) != 3
            or any(x["status"] != "UNATTRIBUTED" for x in result["external_events"])
            or result["causal_links"] or result["matched_instructions"]
            or result["unresolved_observations"]):
        raise ValueError("external event attribution boundary violated")
    return {
        "status": "SYNTHETIC_SYSCALL_AS_UNATTRIBUTED_FILE_EVENTS_PASS",
        "native_trace_sha256": receipt["trace_sha256"],
        "executable_sha256": receipt["executable_sha256"],
        "correlation_input_sha256": result["input_sha256"],
        "external_events": result["external_events"],
        "causal_links": result["causal_links"],
        "matched_instructions": result["matched_instructions"],
        "limitations": ["fixed-native-receipt-only", "no-instruction-address-in-strace",
                        "no-function-claim", "same-artifact-native-gdb-not-yet-witnessed",
                        "trace-digest-not-unique-execution-identity"]
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    if a.input.is_symlink() or not a.input.is_file() or a.input.stat().st_size > 65536:
        ap.error("input must be a bounded ordinary native receipt")
    if a.output.exists() or a.output.is_symlink():
        ap.error("output must be a new run-scoped file")
    receipt = project(json.loads(a.input.read_text(encoding="utf-8")))
    with a.output.open("x", encoding="utf-8") as fp:
        fp.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(receipt["status"])


if __name__ == "__main__":
    main()
