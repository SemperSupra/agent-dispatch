#!/usr/bin/env python3
"""Qualify outside RE primitives on public synthetic fixtures only.

The adopted control plane retains all decisions; this is a test-class runner,
not a candidate decompiler, agent, or new scheduler.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import statistics
import struct
import subprocess
import sys
import time

PIN = {
    "asc": "464f9fef0db41099c4cf3f55c78b33f2606780d2",
    "agentre": "654c4042bb0022b32b522769d99f76b103f5d504",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_head(folder):
    proc = subprocess.run(
        ["git", "-C", str(folder), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=15
    )
    return proc.stdout.strip()


def record(result, name, truth, observed, extra=None):
    result["cases"].append({
        "id": name,
        "expected": truth,
        "observed": observed,
        "pass": truth == observed,
        **(extra or {}),
    })


def asc_experiment(root, result):
    sys.path[0:0] = [str(root), str(root / "tests")]
    from dex_fixture import make_dex, make_invoke_dex, make_instance_field_dex
    from droidasc.asc_client.asc_handler import AscHandler

    fixture = make_dex()
    result["fixtures"] = {
        "shared_code_dex_sha256": sha(fixture),
        "invoke_dex_sha256": sha(make_invoke_dex()),
        "instance_field_dex_sha256": sha(make_instance_field_dex()),
    }
    record(result, "raw_dex_magic", True, fixture.startswith(b"dex\n035\x00"))
    record(result, "raw_method_count", 2, struct.unpack_from("<I", fixture, 0x58)[0])
    # Truly independent of the candidate parser: read the two code offsets from
    # the tiny authored DEX class_data ULEB layout; both share the same code body.
    class_defs = struct.unpack_from("<I", fixture, 0x64)[0]
    class_data = struct.unpack_from("<I", fixture, class_defs + 24)[0]
    def uleb(data, off):
        n = shift = 0
        while True:
            v = data[off]
            off += 1
            n |= (v & 0x7f) << shift
            shift += 7
            if not v & 0x80:
                return n, off
    p = class_data
    for _ in range(4):
        _, p = uleb(fixture, p)
    offsets = []
    for _ in range(2):
        _, p = uleb(fixture, p)  # method idx delta
        _, p = uleb(fixture, p)  # flags
        ofs, p = uleb(fixture, p)
        offsets.append(ofs)
    record(result, "byte_independent_shared_body", True, bool(offsets[0] == offsets[1] and offsets[0] > 0))

    handler = AscHandler()
    cases = [
        ("string_shared_body", fixture, "token", {"first", "second"}),
        ("absent_string", fixture, "__absent_keyword__", set()),
    ]
    for name, data, token, expected in cases:
        lines = handler.findrefs("fixture.dex", data, "string", {"string": token})
        names = {ln.split("->", 1)[1].split(" |", 1)[0] for ln in lines}
        record(result, name, sorted(expected), sorted(names), {"lines": len(lines)})
    # Force no method body: ref is absent even if the original string table remains.
    bodyless = bytearray(fixture)
    bodyless[class_data:class_data+10] = b"\0\0\x02\0\0\x09\0\x01\x09\0"
    ref = handler.findrefs("fixture.dex", bytes(bodyless), "string", {"string": "token"})
    record(result, "bodyless_false_positive", [], ref)
    # Damage map entry, demanding class-definitions fallback without false negatives.
    fallback = bytearray(fixture)
    mapoff = struct.unpack_from("<I", fallback, 52)[0]
    count = struct.unpack_from("<I", fallback, mapoff)[0]
    for pos in range(mapoff + 4, mapoff + 4 + count * 12, 12):
        if struct.unpack_from("<H", fallback, pos)[0] == 0x2000:
            struct.pack_into("<H", fallback, pos, 0xffff)
    got = handler.findrefs("fixture.dex", bytes(fallback), "string", {"string": "token"})
    names = {ln.split("->", 1)[1].split(" |", 1)[0] for ln in got}
    record(result, "missing_map_fallback", ["first", "second"], sorted(names))

    times = []
    for _ in range(11):
        t = time.perf_counter_ns()
        lines = handler.findrefs("fixture.dex", fixture, "string", {"string": "token"})
        times.append((time.perf_counter_ns() - t) / 1e6)
        if len(lines) != 2:
            raise AssertionError("Non-repeatable reference count")
    result["latency_diagnostic_ms"] = {
        "n": len(times), "median": round(statistics.median(times), 5),
        "min": round(min(times), 5), "max": round(max(times), 5),
        "warning": "tiny artificial DEX only; not a performance comparison"
    }
    # The published regression itself must pass on exact upstream sources.
    proc = subprocess.run(
        [sys.executable, "-S", "-m", "unittest", "discover", "-s", "tests",
         "-p", "test_references.py", "-v"],
        cwd=root, timeout=45, capture_output=True, text=True
    )
    result["upstream_reference_suite"] = {
        "exit_code": proc.returncode,
        "tail": (proc.stdout + "\n" + proc.stderr)[-1800:],
    }
    record(result, "upstream_reference_suite_exit", 0, proc.returncode)


def agentre_experiment(root, result):
    sys.path.insert(0, str(root))
    from scorer import score_sample
    gt = {
        "sample": "level4_synthetic_nonoperational",
        "tier": "standard", "file_type": "ELF64",
        "encoded_strings": True, "decoded_c2": None, "c2_protocol": None,
        "techniques": ["runtime_polymorphism", "nop_sled", "shellcode_gen"],
    }
    result["fixture_sha256"] = sha(json.dumps(gt, sort_keys=True).encode())
    perfect = {
        "file_type": "ELF64", "encoded_strings": True,
        "decoded_c2": None, "c2_protocol": None,
        "techniques": gt["techniques"],
    }
    baseline = score_sample(gt, perfect)
    record(result, "perfect_exact", 1.0, baseline["final_score"])
    record(result, "null_fields_excluded", False, "decoded_c2" in baseline["field_scores"])
    spurious = score_sample(gt, {**perfect, "decoded_c2": "fake.example:443", "c2_protocol": "TCP"})
    record(result, "spurious_field_penalty", 0.9, round(spurious["final_score"], 6))
    hallucination = score_sample(gt, {**perfect, "techniques": gt["techniques"] + ["unobserved_magic"]})
    record(result, "invented_technique_lower_score", True, hallucination["final_score"] < 1.0)
    missing = score_sample(gt, {**perfect, "techniques": []})
    record(result, "missing_technique_lower_score", True, missing["final_score"] < 1.0)
    wrong_type = score_sample(gt, {**perfect, "file_type": "PE64"})
    record(result, "wrong_binary_family_lower_score", True, wrong_type["final_score"] < 1.0)
    alias = score_sample(gt, {**perfect, "file_type": "ELF64-SO"})
    record(result, "valid_binary_alias", 1.0, alias["final_score"])
    # Important: replacing truth with a null does not grant free points.
    no_techniques = dict(gt, techniques=[])
    no_tech_result = score_sample(no_techniques, dict(perfect, techniques=[]))
    # The scorer emits the zero-truth diagnostic field even when its weight is
    # excluded by its private _renormalize() map. Downstream must not mistake
    # field_scores keys for weighted field inclusion.
    record(result, "null_techniques_diagnostic_emitted", True, "techniques" in no_tech_result["field_scores"])
    record(result, "null_techniques_excluded_from_weight", 1.0, no_tech_result["weighted_score"])
    result["interpretation_warning"] = (
        "field_scores contains diagnostics for excluded ground-truth fields; "
        "use the weighted_score, not sum(field_scores) for acceptance"
    )
    result["raw_scores"] = {
        "perfect": baseline["final_score"],
        "spurious": spurious["final_score"],
        "hallucination": hallucination["final_score"],
        "missing": missing["final_score"],
        "wrong_type": wrong_type["final_score"],
        "alias": alias["final_score"],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--candidate", choices=sorted(PIN), required=True)
    p.add_argument("--checkout", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = {
        "schema": "reverse-engineering-tool-qualification/v1",
        "candidate": a.candidate, "expected_git_sha": PIN[a.candidate],
        "runner_commit": os.environ.get("GITHUB_SHA"),
        "runner_id": os.environ.get("GITHUB_RUN_ID"),
        "scope": "public authored synthetic only; no proprietary artifact or service",
        "cases": [], "status": "NOT_RUN", "phase": "observe_discover",
    }
    try:
        actual = git_head(a.checkout)
        result["actual_git_sha"] = actual
        if actual != PIN[a.candidate]:
            raise ValueError("ref mismatch: exact pin not satisfied")
        result["phase"] = "apply"
        if a.candidate == "asc":
            asc_experiment(a.checkout, result)
        else:
            agentre_experiment(a.checkout, result)
        result["phase"] = "verify"
        result["status"] = "PASS_NARROW_SYNTHETIC" if all(c["pass"] for c in result["cases"]) else "FAIL"
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
        result["status"] = "FAIL_OR_INCOMPLETE"
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS_NARROW_SYNTHETIC" else 1


if __name__ == "__main__":
    sys.exit(main())
