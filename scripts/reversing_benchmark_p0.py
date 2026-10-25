#!/usr/bin/env python3
"""Public synthetic RE-BENCH-P0: bounded, audience-consistent evidence reduction.

Consumes only the existing Ghidra/objdump/GDB no-unwind matrix JSON produced
by the same public workflow. It does not run a target, access private source,
grade unseen reasoning, or authenticate arbitrary hostile debugger stdout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

AUTHORITY = "mark-e-deyoung/ghidra-tools#4"
SCHEMA = "reversing-benchmark-p0/v1"
SHA = re.compile(r"^[0-9a-f]{64}$")
PROFILES = ("O2-no-unwind", "O2-seed2-no-unwind")
ARGS = (0, 1)
NATIVE_HIT = "BREAKPOINT_OBSERVED_AFTER_RDI_INTERVENTION"
NONHIT = "NOT_OBSERVED_IN_THIS_INTERVENED_RUN"
ALLOWED_STATUS = {NATIVE_HIT, NONHIT, "ENTRY_PC_OBSERVED_AND_RDI_ATTESTED"}

class BenchmarkError(ValueError):
    pass

def require(ok, msg):
    if not ok:
        raise BenchmarkError(msg)

def uint(x, limit=(1 << 32)):
    return type(x) is int and 0 <= x < limit

def digest(s):
    return isinstance(s, str) and SHA.fullmatch(s) is not None and s != "0" * 64

def reduce_matrix(doc):
    """Semantic consistency validation, NOT a standalone hostile-native witness."""
    require(isinstance(doc, dict) and doc.get("schema") == "reversing-stripped-contrast/v1"
            and doc.get("result") == "MATRIX_MEASURED_NOT_FULL_RECOVERY_PROOF",
            "invalid fixed native matrix identity")
    profiles = doc.get("profiles")
    require(isinstance(profiles, list) and len(profiles) == 3, "wrong matrix profiles")
    selected = {}
    for p in profiles:
        require(isinstance(p, dict) and isinstance(p.get("profile"), str)
                and p["profile"] not in selected, "duplicate/invalid matrix profile")
        selected[p["profile"]] = p
    require(set(selected) == {"O0-no-unwind", *PROFILES}, "unexpected profile set")
    cases = []
    for name in PROFILES:
        p = selected[name]
        require(p.get("branch_seed") == (3 if name == PROFILES[0] else 2),
                "profile seed mismatch")
        require(p.get("symbol_table_absent") is True
                and p.get("unwind_tables_absent") is True
                and p.get("native_unmodified_fixture_exercised") is True,
                "unqualified stripped binary")
        binary_digest = p.get("stripped_sha256")
        require(digest(binary_digest)
                and p.get("rdi_binary_unchanged_sha256") == binary_digest
                and digest(p.get("original_sha256"))
                and p["original_sha256"] != binary_digest
                and digest(p.get("stripped_original_text_sha256")),
                "invalid, missing or mutable artifact identity")
        intervals = p.get("independent_code_intervals")
        require(isinstance(intervals, list) and len(intervals) == 4,
                "missing independent four-island geometry")
        last_end = -1
        for item in intervals:
            require(isinstance(item, dict)
                    and set(item) == {"start_rva", "end_exclusive_rva"}
                    and uint(item["start_rva"]) and uint(item["end_exclusive_rva"])
                    and last_end < item["start_rva"] < item["end_exclusive_rva"],
                    "invalid or overlapping independent intervals")
            last_end = item["end_exclusive_rva"]
        sym = p.get("oracle_symbol_rva")
        require(uint(sym) and intervals[0]["start_rva"] == sym,
                "symbol/first interval mismatch")
        b = p.get("independent_objdump_boundary_oracle")
        require(isinstance(b, dict)
                and b.get("classification") == "EXACT_OBJDUMP_NONNOP_INTERVALS"
                and b.get("ghidra_interval_count") == 4
                and b.get("objdump_nonnop_interval_count") == 4
                and b.get("missing_nonnop_bytes") == 0
                and b.get("extra_nonoracle_bytes") == 0,
                "independent static structure not exact")
        edge = p.get("independent_signed_branch_oracle")
        require(isinstance(edge, dict)
                and edge.get("status") == "SIGNED_JLE_DIRECT_EDGE_TO_ISLAND_3"
                and edge.get("interval_index") == 3
                and edge.get("width_bits") == 64
                and edge.get("predicate") == "signed_flags_le_zero_at_jle"
                and uint(edge.get("target_rva"))
                and sym + edge["target_rva"] == intervals[3]["start_rva"],
                "signed branch target disagrees with fourth code island")
        rdi = p.get("rdi_intervention")
        require(isinstance(rdi, dict)
                and rdi.get("status") == "RDI_INTERVENTION_ISLAND_SAMPLES_MEASURED"
                and rdi.get("baseline_argument_n") == 7
                and rdi.get("abi") == "X86_64_SYSV_FIRST_ARGUMENT_RDI",
                "native RDI experiment scope changed")
        samples = rdi.get("arguments")
        require(isinstance(samples, list) and len(samples) == 6
                and [r.get("argument_n") for r in samples if isinstance(r, dict)]
                == [1, 4, 8, 12, 0, -1], "unexpected or missing bounded inputs")
        rows = {row["argument_n"]: row for row in samples}
        for n in ARGS:
            row = rows[n]
            statuses = row.get("statuses")
            require(row.get("interval_count") == 4
                    and isinstance(statuses, list) and len(statuses) == 4,
                    "missing native island-specific statuses")
            observed = []
            nonhit = []
            for i, status in enumerate(statuses):
                require(isinstance(status, dict)
                        and status.get("interval_index") == i
                        and status.get("target_delta_from_entry")
                        == intervals[i]["start_rva"] - sym
                        and status.get("status") in ALLOWED_STATUS,
                        "status identity, target PC, or offset mismatch")
                value = status["status"]
                if i == 0:
                    require(value == "ENTRY_PC_OBSERVED_AND_RDI_ATTESTED",
                            "entry is not a native control")
                    observed.append(i)
                elif value == NATIVE_HIT:
                    observed.append(i)
                elif value == NONHIT:
                    nonhit.append(i)
                else:
                    raise BenchmarkError("non-entry status claimed entry")
            require(row.get("observed_indices") == observed
                    and row.get("not_observed_indices") == nonhit,
                    "native indices contradict their detailed evidence")
            target_status = statuses[3]["status"]
            verdict = "NATIVE_PC_WITNESS" if target_status == NATIVE_HIT else "NOT_OBSERVED_SAMPLE"
            require((n == 0 and verdict == "NATIVE_PC_WITNESS")
                    or (n == 1 and verdict == "NOT_OBSERVED_SAMPLE"),
                    "positive/negative synthetic control failed")
            cases.append({
                "claim_id": name + "-island3-n" + str(n),
                "profile": name,
                "input_n": n,
                "interval_index": 3,
                "target_rva": intervals[3]["start_rva"],
                "artifact_sha256": binary_digest,
                "verdict": verdict,
                "scope": "ONE_STRIPPED_ELF_NATIVE_GDB_PC_SAMPLE",
                "oracle": "GNU_OBJDUMP_EDGE_AND_GHIDRA_RANGES_PLUS_NATIVE_GDB_STATUS",
            })
    # Keep code comparison as a real cross-profile falsification constraint.
    require(selected[PROFILES[0]]["stripped_original_text_sha256"]
            == selected[PROFILES[1]]["stripped_original_text_sha256"],
            "the two optimized seed variants do not share identical .text bytes")
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "schema": SCHEMA,
        "work_id": "RE-BENCH-P0",
        "authority_ref": AUTHORITY,
        "exposure_class": "GENERATED_PUBLIC_SYNTHETIC_POSSIBLY_TRAINING_EXPOSED",
        "verifier_kind": "DETERMINISTIC_SECONDARY_MATRIX_CONSISTENCY_NOT_INDEPENDENT_NATIVE_ATTESTATION",
        "source_receipt_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "cases": cases,
        "overall": "P0_FOUR_CONTROLS_CONSISTENT_NOT_SEALED_BLIND",
        "limitations": [
            "Only generated Linux x86-64 SysV GCC ELF and fixed input cases",
            "A PC sample is not entire-island coverage or an executed-edge trace",
            "No-hit is not unreachability",
            "Producer and reducer are in one public CI authority, not a sealed independent evaluator",
            "Raw GDB console text is not a hostile-inferior-authenticated channel",
            "Shape/semantic consistency cannot independently rederive raw debugger bytes or ELF SHA",
            "Not qualified for real binaries, protected graders, model rankings, releases or merges",
        ],
    }

def render_markdown(r):
    require(isinstance(r, dict) and r.get("schema") == SCHEMA, "bad report to render")
    lines = [
        "# RE-BENCH-P0 — public synthetic evidence",
        "",
        "Status: **" + r["overall"] + "**",
        "",
        "Authority: " + r["authority_ref"],
        "Work item: " + r["work_id"],
        "Exposure: " + r["exposure_class"],
        "Verifier: " + r["verifier_kind"],
        "Source receipt SHA-256: \`" + r["source_receipt_sha256"] + "\`",
        "",
        "| Claim ID | Argument | Native sample verdict | Target RVA |",
        "| --- | ---: | --- | --- |",
    ]
    for c in r["cases"]:
        lines.append("| " + c["claim_id"] + " | " + str(c["input_n"]) + " | "
                     + c["verdict"] + " | 0x" + format(c["target_rva"], "x") + " |")
    lines += ["", "## Scientific and admission limits", ""]
    for item in r["limitations"]:
        lines.append("- " + item)
    lines += ["", "The JSON report and this Markdown report are projections of the SAME claim IDs and outcomes.", ""]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True, help="same-run public synthetic contrast receipt")
    ap.add_argument("--json-output", type=Path, required=True)
    ap.add_argument("--markdown-output", type=Path, required=True)
    args = ap.parse_args()
    if args.input.is_symlink() or not args.input.is_file() or args.input.stat().st_size > 2_097_152:
        ap.error("ordinary bounded matrix JSON required")
    try:
        result = reduce_matrix(json.loads(args.input.read_text(encoding="utf-8")))
    except (ValueError, UnicodeError) as exc:
        ap.error("evidence refused: " + str(exc))
    args.json_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_output.write_text(render_markdown(result), encoding="utf-8")
    print(result["overall"])

if __name__ == "__main__":
    main()
