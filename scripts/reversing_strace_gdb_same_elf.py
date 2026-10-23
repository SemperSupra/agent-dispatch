#!/usr/bin/env python3
"""Two independent runtime observations on one generated ELF (NOT one run).

Reuses the qualified bounded fixed-fixture strace collector, its existing v1
external-event projection and the native GDB parser. No arbitrary targets,
private samples, privileged attaches, cross-sensor causality or new schema owner.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "scripts"


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TRACE = module("reversing_strace_fixture_probe.py", "same_elf_strace")
PROJECTION = module("reversing_strace_v1_projection.py", "same_elf_projection")
NATIVE = module("reversing_native_elf_probe.py", "same_elf_gdb")
CORR = module("reversing_evidence_correlate.py", "same_elf_correlator")


class OracleError(ValueError):
    pass


def parse_main_symbol(output):
    matches = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in {"T", "t"} and fields[3] == "main":
            try:
                matches.append((int(fields[0], 16), int(fields[1], 16)))
            except ValueError as exc:
                raise OracleError("invalid main symbol address or size") from exc
    if len(matches) != 1 or matches[0][1] < 1:
        raise OracleError("main symbol must be unique with positive size")
    return matches[0]


def correlate_separate_runs(trace_receipt, gdb_pc, symbol, size, base, image_size, actual_executable_sha, gdb_file_bytes):
    """Correlate separately; require bit-identical ELF but never join run IDs."""
    if not isinstance(actual_executable_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", actual_executable_sha):
        raise OracleError("bad computed binary digest")
    if trace_receipt.get("executable_sha256") != actual_executable_sha:
        raise OracleError("trace and GDB target digest mismatch")
    if gdb_file_bytes != TRACE.PAYLOAD:
        raise OracleError("GDB execution did not independently produce exact output")
    if (type(symbol) is not int or type(size) is not int or type(base) is not int
            or type(image_size) is not int or type(gdb_pc) is not int
            or size < 1 or image_size < 1 or base < 1):
        raise OracleError("invalid numeric image or GDB oracle")
    if not (base <= symbol < symbol + size <= base + image_size):
        raise OracleError("main symbol outside independent ELF image")
    if not symbol <= gdb_pc < symbol + size:
        raise OracleError("native GDB PC not in main symbol body")

    trace_projection = PROJECTION.project(trace_receipt)
    if trace_projection["executable_sha256"] != actual_executable_sha:
        raise OracleError("strace v1 projection points to different ELF")
    gdb_run_id = "fixed-gdb-separate-run"
    doc = {
        "schema": CORR.INPUT_SCHEMA, "run_id": gdb_run_id, "mode": "synthetic",
        "artifact_sha256": actual_executable_sha,
        "functions": [{"id": "main", "rva": symbol - base, "size": size}],
        "module_loads": [{"id": "elf-main", "artifact_sha256": actual_executable_sha,
                          "base_va": base, "size": image_size}],
        "events": [{"id": "gdb-main-breakpoint", "kind": "instruction", "sensor": "native-gdb",
                    "vantage": "guest", "run_id": gdb_run_id,
                    "time_domain": "gdb-separate-inferior", "module_load_id": "elf-main", "va": gdb_pc}],
    }
    mapped = CORR.correlate(doc)
    if (len(mapped["matched_instructions"]) != 1
            or mapped["matched_instructions"][0]["function_id"] != "main"
            or mapped["unresolved_observations"] or mapped["causal_links"]
            or trace_projection["matched_instructions"] or trace_projection["causal_links"]
            or len(trace_projection["external_events"]) != 3
            or any(e["status"] != "UNATTRIBUTED" for e in trace_projection["external_events"])):
        raise OracleError("cross-sensor attribution or address mapping invariant failed")
    return {
        "schema": "reversing-fixed-elf-dual-observation/v0.1",
        "status": "SAME_ELF_TWO_NATIVE_OBSERVATIONS_NO_CROSS_RUN_CAUSE",
        "relationship": "SAME_COMPILED_ELF_DISTINCT_INFERIORS",
        "executable_sha256": actual_executable_sha,
        "gdb_main_pc_rva": gdb_pc - base,
        "gdb_main_symbol_rva": symbol - base,
        "strace_trace_sha256": trace_receipt["trace_sha256"],
        "strace_file_output_sha256": trace_receipt["output_sha256"],
        "gdb_file_output_sha256": TRACE.sha256(gdb_file_bytes),
        "gdb_matched_instructions": mapped["matched_instructions"],
        "strace_unattributed_file_events": trace_projection["external_events"],
        "cross_run_causal_links": [],
        "limitations": ["separate-process-executions-not-concurrent", "no-syscall-callsite",
                        "no-proof-that-GDB-observed-strace-inferior",
                        "no-code-attribution-from-temporal-proximity",
                        "synthetic-known-source-only"],
    }


def execute():
    for command in ("gcc", "nm", "readelf", "strace", "gdb"):
        if shutil.which(command) is None:
            raise OracleError("BLOCKED_CAPABILITY: missing " + command)
    with tempfile.TemporaryDirectory(prefix="reversing-dual-fixture-") as temporary:
        root = Path(temporary)
        source, exe = root / "fixed.c", root / "fixed"
        source.write_text(TRACE.SOURCE, encoding="utf-8")
        TRACE.run_checked(["gcc", "-std=c11", "-O0", "-g", "-fno-pie", "-no-pie",
                           "-Wall", "-Wextra", "-Werror", "-o", str(exe), str(source)],
                          cwd=temporary, timeout=30)
        digest = TRACE.sha256(exe.read_bytes())
        symbol, size = parse_main_symbol(TRACE.run_checked(
            ["nm", "-n", "-S", "--defined-only", str(exe)],
            cwd=temporary, timeout=10).stdout.decode("utf-8", errors="strict"))
        base, image_size = NATIVE.parse_image(TRACE.run_checked(
            ["readelf", "-W", "-l", str(exe)],
            cwd=temporary, timeout=10).stdout.decode("utf-8", errors="strict"))

        trace_dir, gdb_dir = root / "strace-run", root / "gdb-run"
        trace_dir.mkdir()
        gdb_dir.mkdir()
        trace_file = trace_dir / "trace.txt"
        TRACE.run_checked(["strace", "-s", "64", "-e",
                           "trace=openat,write,close,exit_group",
                           "-o", str(trace_file), "--", str(exe)],
                          cwd=str(trace_dir), timeout=20)
        trace_data = trace_file.read_bytes()
        trace_facts = TRACE.check_trace(trace_data.decode("utf-8", errors="strict"))
        trace_output = (trace_dir / TRACE.FILE).read_bytes()
        if trace_output != TRACE.PAYLOAD:
            raise OracleError("strace-run file oracle failed")
        trace_receipt = {
            "schema": "strace-fixed-fixture-receipt/v0.1",
            "scope": "synthetic-generated-linux-elf-only",
            "status": "NATIVE_SYSCALL_TRACE_FIXTURE_PASS",
            "source_sha256": TRACE.sha256(TRACE.SOURCE.encode()),
            "executable_sha256": digest,
            "trace_sha256": TRACE.sha256(trace_data),
            "output_sha256": TRACE.sha256(trace_output),
            "observed": trace_facts,
        }
        gdb_output = TRACE.run_checked([
            "gdb", "--batch", "--nx", "--quiet", str(exe),
            "-ex", "set pagination off", "-ex", "break main",
            "-ex", "run", "-ex", 'printf "RE_PC=%p\\n", $pc',
            "-ex", "continue"
        ], cwd=str(gdb_dir), timeout=40).stdout.decode("utf-8", errors="strict")
        pc = NATIVE.parse_gdb_pc(gdb_output)
        if TRACE.sha256(exe.read_bytes()) != digest:
            raise OracleError("target ELF bytes changed between measurements")
        result = correlate_separate_runs(
            trace_receipt, pc, symbol, size, base, image_size,
            digest, (gdb_dir / TRACE.FILE).read_bytes())
        result["source_sha256"] = TRACE.sha256(TRACE.SOURCE.encode())
        result["gdb_stdout_sha256"] = TRACE.sha256(gdb_output.encode("utf-8"))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise OracleError("refuse existing output receipt")
    result = execute()
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(result["status"])


if __name__ == "__main__":
    main()
