#!/usr/bin/env python3
"""Exact generated-ELF + nm/readelf static symbols + native GDB execution oracle.

Runs only a fixed, public synthetic C fixture in a fresh temporary directory.
This is not a generic debugger or a workload executor; never accepts target
source, a binary path, arbitrary GDB commands or a network endpoint.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CORRELATOR = ROOT / "scripts" / "reversing_evidence_correlate.py"
SPEC = importlib.util.spec_from_file_location("correlator", CORRELATOR)
CORR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORR)
FIXTURE = """#include <stdint.h>
__attribute__((noinline)) int fixture_target(int n) {
    volatile int result = n * 3;
    return result + 1;
}
int main(void) { return fixture_target(7) == 22 ? 0 : 3; }
"""
TARGET = "fixture_target"


class OracleError(RuntimeError):
    pass


def run(argv, timeout=30):
    cp = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                        text=True, check=False, timeout=timeout)
    if cp.returncode != 0:
        raise OracleError("tool execution failed: " + argv[0] + "; rc=" + str(cp.returncode))
    return cp.stdout


def parse_symbol(nm_output):
    rows = []
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[2] in {"T", "t"} and fields[3] == TARGET:
            rows.append((int(fields[0], 16), int(fields[1], 16)))
    if len(rows) != 1 or rows[0][1] < 1:
        raise OracleError("expected one unambiguous fixture function symbol")
    return rows[0]


def parse_image(readelf_output):
    segments = []
    for line in readelf_output.splitlines():
        fields = line.split()
        if fields and fields[0] == "LOAD" and len(fields) >= 6:
            start = int(fields[2], 16)
            size = int(fields[5], 16)
            if size:
                segments.append((start, start + size))
    if not segments:
        raise OracleError("no ELF load segments")
    start = min(a for a, _ in segments)
    end = max(b for _, b in segments)
    if start <= 0 or end <= start:
        raise OracleError("invalid non-PIE ELF virtual address layout")
    return start, end - start


def parse_gdb_pc(text):
    points = re.findall(r"^RE_PC=0x([0-9a-fA-F]+)\s*$", text, re.MULTILINE)
    if len(points) != 1:
        raise OracleError("GDB did not observe exactly one breakpoint program counter")
    if not re.search(r"exited normally", text, re.IGNORECASE):
        raise OracleError("GDB did not verify successful process exit")
    return int(points[0], 16)


def execute():
    for program in ("gcc", "nm", "readelf", "gdb"):
        if shutil.which(program) is None:
            raise OracleError("required public runner tool missing: " + program)
    with tempfile.TemporaryDirectory(prefix="reversing-native-elf-") as directory:
        temp = Path(directory)
        source = temp / "fixture.c"
        binary = temp / "fixture"
        source.write_text(FIXTURE, encoding="utf-8")
        run(["gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-fno-omit-frame-pointer",
             "-Wall", "-Wextra", "-o", str(binary), str(source)])
        # The uninstrumented fixture's independent program oracle must pass.
        run([str(binary)], timeout=5)
        symbol, length = parse_symbol(run(["nm", "-n", "-S", "--defined-only", str(binary)]))
        base, total = parse_image(run(["readelf", "-W", "-l", str(binary)]))
        if not base <= symbol < base + total or symbol + length > base + total:
            raise OracleError("symbol not inside exact ELF memory image")
        from hashlib import sha256
        digest = sha256(binary.read_bytes()).hexdigest()
        gdb_output = run(["gdb", "--batch", "--nx", "--quiet", str(binary),
                          "-ex", "set pagination off",
                          "-ex", "break fixture_target",
                          "-ex", "run",
                          "-ex", 'printf "RE_PC=%p\\n", $pc',
                          "-ex", "continue"], timeout=35)
        pc = parse_gdb_pc(gdb_output)
        document = {
            "schema": CORR.INPUT_SCHEMA, "run_id": "generated-elf-native-001",
            "mode": "synthetic", "artifact_sha256": digest,
            "functions": [{"id": TARGET, "rva": symbol - base, "size": length}],
            "module_loads": [{"id": "main-executable", "artifact_sha256": digest,
                              "base_va": base, "size": total}],
            "events": [{"id": "gdb-breakpoint-1", "kind": "instruction",
                        "sensor": "native-gdb", "vantage": "guest",
                        "run_id": "generated-elf-native-001", "time_domain": "debugger-session",
                        "module_load_id": "main-executable", "va": pc}],
        }
        result = CORR.correlate(document)
        if pc != symbol or len(result["matched_instructions"]) != 1:
            raise OracleError("independent debugger/static symbol identity oracle failed")
        if result["matched_instructions"][0]["function_id"] != TARGET:
            raise OracleError("wrong recovered function")
        return {
            "schema": "reversing-native-elf-receipt/v1",
            "qualification": "NATIVE_SYNTHETIC_ELF_RUNTIME_PASS",
            "artifact_sha256": digest,
            "static_symbol_rva": symbol - base,
            "runtime_observed_rva": pc - base,
            "function_id": TARGET,
            "correlation_input_sha256": result["input_sha256"],
            "matched_instruction_count": len(result["matched_instructions"]),
            "unresolved_instruction_count": len(result["unresolved_observations"]),
            "limitations": [
                "synthetic-generated-elf-only", "native-gdb-not-qemu-or-hyper-v",
                "source-and-symbols-present", "no-real-target-or-private-data",
                "no-process-network-file-memory-or-driver-observability",
                "no-general-code-recovery-or-semantic-equivalence-proof",
            ],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = execute()
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(receipt["qualification"])


if __name__ == "__main__":
    main()
