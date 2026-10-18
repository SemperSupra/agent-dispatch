#!/usr/bin/env python3
"""Bounded x86-64 Linux stripped-ELF / no-unwind Ghidra qualification matrix.

Public synthetic source only. The separate original build provides the
independent symbol oracle; Ghidra/GDB receive only the stripped binary. A
negative discovery result remains a measured result, never a synthetic PASS.
"""
import argparse
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "native_reversing", ROOT / "scripts" / "reversing_native_elf_probe.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
EXPORT_SCRIPT = ROOT / "scripts" / "ghidra" / "ReversingExportFunctions.java"
SOURCE = r'''
volatile long branch_seed = 3;
__attribute__((noinline,used)) long fixture_target(long n) {
    long result = n;
    for (long i = 0; i < n; ++i) {
        if ((i ^ branch_seed) & 1) {
            result += i * (n + 1);
        } else if (result & 2) {
            result -= i + 1;
        } else {
            result ^= i + n;
        }
    }
    return result;
}
void _start(void) {
    volatile long answer = fixture_target(7);
    (void)answer;
#if defined(__x86_64__)
    __asm__ volatile("mov $60, %%rax\nxor %%rdi, %%rdi\nsyscall"
                     ::: "rax", "rdi", "rcx", "r11", "memory");
#else
#error "Only x86-64 Linux is qualified"
#endif
    __builtin_unreachable();
}
'''
PROFILES = ("O0-no-unwind", "O2-no-unwind")
OUTCOMES = {
    "ENTRY_NOT_FOUND", "AMBIGUOUS_ENTRY", "INVALID_FUNCTION_BODY",
    "BODY_EXTENDS_BEYOND_ORACLE", "PARTIAL_BODY", "EXACT_BODY",
}

class MatrixError(ValueError):
    pass


def function_assessment(export, symbol, size, image_base):
    """Never use a source name to select the stripped candidate."""
    if not isinstance(export, dict) or set(export) != {
            "schema", "image_base", "executable_format", "functions"}:
        raise MatrixError("invalid Ghidra export")
    if export["schema"] != "ghidra-function-ranges/v1" or "ELF" not in str(export["executable_format"]):
        raise MatrixError("invalid Ghidra exporter identity")
    if not isinstance(export["image_base"], str) or not export["image_base"].isdigit():
        raise MatrixError("invalid program image base")
    if int(export["image_base"]) != image_base:
        raise MatrixError("Ghidra image base differs from ELF oracle")
    fs = export["functions"]
    if not isinstance(fs, list) or len(fs) > 1024:
        raise MatrixError("unbounded Ghidra functions")
    candidates = [f for f in fs if isinstance(f, dict) and f.get("entry") == str(symbol)]
    if not candidates:
        return {"outcome": "ENTRY_NOT_FOUND", "recovered_bytes": 0, "oracle_bytes": size}
    if len(candidates) != 1:
        return {"outcome": "AMBIGUOUS_ENTRY", "recovered_bytes": 0, "oracle_bytes": size}
    f = candidates[0]
    if set(f) != {"name", "entry", "ranges"} or not isinstance(f["ranges"], list):
        return {"outcome": "INVALID_FUNCTION_BODY", "recovered_bytes": 0, "oracle_bytes": size}
    if len(f["ranges"]) != 1:
        return {"outcome": "INVALID_FUNCTION_BODY",
                "diagnostic": "MULTIRANGE_OR_EMPTY_BODY",
                "reported_range_count": len(f["ranges"]),
                "recovered_bytes": 0, "oracle_bytes": size}
    r = f["ranges"][0]
    if not isinstance(r, dict) or set(r) != {"start", "end_exclusive"}:
        return {"outcome": "INVALID_FUNCTION_BODY", "recovered_bytes": 0, "oracle_bytes": size}
    if not all(isinstance(r[k], str) and re.fullmatch(r"[0-9]+", r[k]) for k in ("start", "end_exclusive")):
        return {"outcome": "INVALID_FUNCTION_BODY", "recovered_bytes": 0, "oracle_bytes": size}
    a, b = int(r["start"]), int(r["end_exclusive"])
    if a != symbol or b <= a:
        return {"outcome": "INVALID_FUNCTION_BODY",
                "diagnostic": "BODY_START_OR_ORDER_INVALID",
                "start_delta_from_entry": a-symbol,
                "recovered_bytes": 0, "oracle_bytes": size}
    if b > symbol + size:
        return {"outcome": "BODY_EXTENDS_BEYOND_ORACLE", "recovered_bytes": b-a, "oracle_bytes": size}
    return {"outcome": "EXACT_BODY" if b == symbol + size else "PARTIAL_BODY",
            "recovered_bytes": b-a, "oracle_bytes": size}


def run_program(argv, timeout=30):
    try:
        return NATIVE.run(argv, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as ex:
        raise MatrixError("fixed fixture tool could not execute") from ex


def observe(ghidra_home, profile):
    if profile not in PROFILES:
        raise MatrixError("unregistered profile")
    with tempfile.TemporaryDirectory(prefix="reversing-matrix-") as td:
        d = Path(td)
        src, original, stripped = (d / n for n in ("fixture.c", "original", "stripped"))
        src.write_text(SOURCE, encoding="utf-8")
        flags = ["-O0"] if profile.startswith("O0") else ["-O2"]
        run_program(["gcc", *flags, "-nostdlib", "-static", "-fno-pie", "-no-pie",
                     "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
                     "-fno-stack-protector", "-fno-tree-vectorize",
                     "-Wl,--build-id=none", "-Wl,-e,_start", "-o", str(original), str(src)])
        run_program([str(original)], timeout=5)
        sym, size = NATIVE.parse_symbol(
            run_program(["nm", "-n", "-S", "--defined-only", str(original)]))
        image_base, image_size = NATIVE.parse_image(
            run_program(["readelf", "-W", "-l", str(original)]))
        sections_before = run_program(["readelf", "-W", "-S", str(original)])
        if not image_base <= sym < sym + size <= image_base + image_size:
            raise MatrixError("symbol outside ELF image")
        if any(name in sections_before for name in (".eh_frame", ".eh_frame_hdr")):
            raise MatrixError("compiler/linker failed no-unwind fixture constraint")
        shutil.copy2(original, stripped)
        run_program(["strip", "--strip-all", str(stripped)])
        sections = run_program(["readelf", "-W", "-S", str(stripped)])
        if any(name in sections for name in (".symtab", ".eh_frame", ".eh_frame_hdr")):
            raise MatrixError("stripped fixture still contains ordinary symbols or unwind tables")
        if NATIVE.TARGET in run_program(["nm", "-D", str(stripped)]):
            raise MatrixError("stripped fixture leaks target dynamic symbol")
        if sha256(original.read_bytes()).digest() == sha256(stripped.read_bytes()).digest():
            raise MatrixError("stripped binary and ground truth share bytes")
        run_program([str(stripped)], timeout=5)
        if NATIVE.parse_image(run_program(["readelf", "-W", "-l", str(stripped)])) != (image_base, image_size):
            raise MatrixError("post-strip segment change")
        dbg = run_program(["gdb", "--batch", "--nx", "--quiet", str(stripped),
                           "-ex", "set pagination off", "-ex", "break *0x%x" % sym,
                           "-ex", "run", "-ex", 'printf "RE_PC=%p\\n", $pc',
                           "-ex", "continue"], timeout=35)
        pc = NATIVE.parse_gdb_pc(dbg)
        if pc != sym:
            raise MatrixError("GDB runtime entry oracle mismatch")
        project = d / "ghidra-projects"
        project.mkdir(mode=0o700)
        exported = d / "export.json"
        argv = [str(ghidra_home / "support" / "analyzeHeadless"), str(project),
                "synthetic-matrix", "-import", str(stripped),
                "-scriptPath", str(EXPORT_SCRIPT.parent),
                "-postScript", EXPORT_SCRIPT.name, str(exported),
                "-max-cpu", "2", "-analysisTimeoutPerFile", "120", "-deleteProject"]
        process = subprocess.run(argv, capture_output=True, text=True,
                                 stdin=subprocess.DEVNULL, timeout=240, check=False)
        if process.returncode != 0 or not exported.is_file() or exported.stat().st_size > 2097152:
            raise MatrixError("Ghidra headless infrastructure/export failure")
        assessment = function_assessment(json.loads(exported.read_text(encoding="utf-8")), sym, size, image_base)
        if assessment["outcome"] not in OUTCOMES:
            raise MatrixError("unknown assessment outcome")
        return {"profile": profile, "outcome": assessment["outcome"],
                "oracle_symbol_rva": sym-image_base, "gdb_pc_rva": pc-image_base,
                "recovered_bytes": assessment["recovered_bytes"],
                "oracle_bytes": size,
                "diagnostic": assessment.get("diagnostic"),
                "reported_range_count": assessment.get("reported_range_count"),
                "start_delta_from_entry": assessment.get("start_delta_from_entry"),
                "original_sha256": sha256(original.read_bytes()).hexdigest(),
                "stripped_sha256": sha256(stripped.read_bytes()).hexdigest(),
                "symbol_table_absent": True, "unwind_tables_absent": True,
                "native_unmodified_fixture_exercised": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-home", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    home = args.ghidra_home.resolve()
    if not (home / "support" / "analyzeHeadless").is_file():
        parser.error("missing pinned Ghidra")
    if any(shutil.which(t) is None for t in ("gcc", "strip", "nm", "readelf", "gdb")):
        parser.error("missing fixed test tools")
    assessments = [observe(home, p) for p in PROFILES]
    report = {
        "schema": "reversing-stripped-contrast/v1",
        "result": "MATRIX_MEASURED_NOT_FULL_RECOVERY_PROOF",
        "profiles": assessments,
        "known_limits": ["x86-64-linux-static-no-crt-only",
                         "fixed-synthetic-cfg", "original-symbol-oracle-exists-only-outside-analyzed-binary",
                         "Ghidra-body-bytes-not-path-completeness",
                         "no-VM-or-external-sensors",
                         "no-Windows-Android-or-FRITZ", "no-source-equivalence-proof"]
    }
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    for item in assessments:
        print("MEASURED_PROFILE=" + item["profile"] + ":" + item["outcome"] +
              (":" + item["diagnostic"] if item["diagnostic"] else "") +
              (":ranges=" + str(item["reported_range_count"])
               if item["reported_range_count"] is not None else ""))
    print(report["result"])


if __name__ == "__main__":
    main()
