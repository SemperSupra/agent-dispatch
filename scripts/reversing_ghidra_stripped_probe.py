#!/usr/bin/env python3
"""Qualify headless Ghidra function discovery with a real stripped ELF target.

An unstripped *separate* build establishes address/size ground truth. A
byte-different stripped copy is the only binary given to Ghidra and GDB.
No arbitrary input, target code, runtime parameters or source paths accepted.
"""
import argparse
import importlib.util
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "scripts" / "reversing_ghidra_headless_probe.py"
S = importlib.util.spec_from_file_location("reversing_ghidra_base", P)
base = importlib.util.module_from_spec(S)
S.loader.exec_module(base)
native = base.native

class StrippedOracleError(ValueError):
    pass

def parse_stripped_export(raw, independent_entry, independent_size, elf_load_base):
    if not isinstance(raw, dict) or set(raw) != {"schema", "image_base", "executable_format", "functions"}:
        raise StrippedOracleError("bad headless export envelope")
    if raw["schema"] != "ghidra-function-ranges/v1" or "ELF" not in str(raw["executable_format"]):
        raise StrippedOracleError("wrong format/schema")
    if not isinstance(raw["functions"], list) or len(raw["functions"]) > 1024:
        raise StrippedOracleError("invalid function list")
    candidates = [f for f in raw["functions"]
                  if isinstance(f, dict) and f.get("entry") == str(independent_entry)]
    if len(candidates) != 1:
        raise StrippedOracleError("unknown/ambiguous discovered entry")
    f = candidates[0]
    if set(f) != {"name", "entry", "ranges"} or not isinstance(f["name"], str):
        raise StrippedOracleError("invalid function data")
    intervals = f["ranges"]
    if not isinstance(intervals, list) or len(intervals) != 1:
        raise StrippedOracleError("noncontiguous/ambiguous recovered function")
    a = intervals[0]
    if not isinstance(a, dict) or set(a) != {"start", "end_exclusive"}:
        raise StrippedOracleError("invalid body interval")
    if any(not isinstance(a[k], str) or not a[k].isdigit() for k in ("start", "end_exclusive")):
        raise StrippedOracleError("invalid body address")
    start, end = int(a["start"]), int(a["end_exclusive"])
    if not elf_load_base <= start == independent_entry < end <= independent_entry + independent_size:
        raise StrippedOracleError("stripped function body differs from independent address oracle")
    return {"id": "stripped_function_recovered", "rva": start - elf_load_base, "size": end - start}


def execute(ghidra_home):
    analyze = Path(ghidra_home).resolve() / "support" / "analyzeHeadless"
    if not analyze.is_file():
        raise StrippedOracleError("pinned Ghidra installation missing")
    for executable in ("gcc", "nm", "readelf", "strip", "gdb"):
        if shutil.which(executable) is None:
            raise StrippedOracleError("missing required binary utility: " + executable)
    with tempfile.TemporaryDirectory(prefix="reversing-stripped-") as td:
        d = Path(td)
        source, original, stripped = d / "fixture.c", d / "original", d / "stripped"
        source.write_text(native.FIXTURE, encoding="utf-8")
        native.run(["gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-fno-omit-frame-pointer",
                    "-Wall", "-Wextra", "-o", str(original), str(source)])
        original_hash = sha256(original.read_bytes()).hexdigest()
        symbol, size = native.parse_symbol(native.run(["nm", "-n", "-S", "--defined-only", str(original)]))
        image_base, image_size = native.parse_image(native.run(["readelf", "-W", "-l", str(original)]))
        shutil.copyfile(original, stripped)
        native.run(["strip", "--strip-all", str(stripped)])
        stripped_hash = sha256(stripped.read_bytes()).hexdigest()
        if stripped_hash == original_hash or native.TARGET in native.run(["nm", "-D", str(stripped)]):
            raise StrippedOracleError("fixture not demonstrably stripped")
        nm = subprocess.run(["nm", "--defined-only", str(stripped)], capture_output=True,
                            text=True, stdin=subprocess.DEVNULL, timeout=5)
        # GNU nm can return zero for a stripped file with no symbol output.
        # Prove the ordinary ELF .symtab section is absent independently.
        sections = native.run(["readelf", "-W", "-S", str(stripped)])
        if (".symtab" in sections or native.TARGET in nm.stdout
                or native.TARGET in native.run(["nm", "-D", str(stripped)])):
            raise StrippedOracleError("ordinary symbol table or target name remains")
        native.run([str(stripped)], timeout=5)
        stripped_base, stripped_size = native.parse_image(native.run(["readelf", "-W", "-l", str(stripped)]))
        if (stripped_base, stripped_size) != (image_base, image_size):
            raise StrippedOracleError("stripping changed ELF load-address oracle")
        proj = d / "projects"
        proj.mkdir()
        export = d / "ghidra-export.json"
        command = [str(analyze), str(proj), "stripped-fixture", "-import", str(stripped),
                   "-scriptPath", str(ROOT / "scripts" / "ghidra"),
                   "-postScript", "ReversingExportFunctions.java", str(export),
                   "-max-cpu", "2", "-analysisTimeoutPerFile", "120", "-deleteProject"]
        p = subprocess.run(command, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=240, check=False)
        if p.returncode != 0 or not export.is_file() or export.stat().st_size > base.MAX_EXPORT:
            detail = "\n".join(line[:180] for line in (p.stdout+"\n"+p.stderr).splitlines()
                               if any(k in line.lower() for k in ("error","exception","failed","script")))[-1200:]
            raise StrippedOracleError("headless export not completed: " + detail)
        found = parse_stripped_export(json.loads(export.read_text()), symbol, size, image_base)
        gdb = native.run(["gdb", "--batch", "--nx", "--quiet", str(stripped),
                          "-ex", "set pagination off", "-ex", "break *0x%x" % symbol,
                          "-ex", "run", "-ex", 'printf "RE_PC=%p\\n", $pc',
                          "-ex", "continue"], timeout=35)
        pc = native.parse_gdb_pc(gdb)
        if pc != symbol:
            raise StrippedOracleError("original independent breakpoint address not observed")
        x = {"schema": native.CORR.INPUT_SCHEMA, "run_id": "ghidra-stripped-001",
             "mode": "synthetic", "artifact_sha256": stripped_hash,
             "functions": [found],
             "module_loads": [{"id": "stripped-main", "artifact_sha256": stripped_hash,
                               "base_va": image_base, "size": image_size}],
             "events": [{"id": "gdb-stripped-entry", "kind": "instruction",
                         "sensor": "native-gdb", "vantage": "guest",
                         "run_id": "ghidra-stripped-001", "time_domain": "debugger",
                         "module_load_id": "stripped-main", "va": pc}]}
        result = native.CORR.correlate(x)
        if len(result["matched_instructions"]) != 1 or result["unresolved_observations"]:
            raise StrippedOracleError("recovered stripped function failed runtime join")
        return {"schema": "reversing-stripped-ghidra-gdb-receipt/v1",
                "qualification": "NATIVE_STRIPPED_ELF_GHIDRA_GDB_PASS",
                "original_symbol_artifact_sha256": original_hash,
                "actual_stripped_artifact_sha256": stripped_hash,
                "symbol_removed": True, "oracle_symbol_rva": symbol - image_base,
                "ghidra_recovered_function_rva": found["rva"],
                "gdb_stripped_runtime_rva": pc - image_base,
                "functions_correlated": 1, "input_sha256": result["input_sha256"],
                "limitations": ["synthetic-elf-known-source", "independent-unstripped-build-oracle",
                                "no-windows-android-or-firmware", "no-VM-sensors",
                                "no-general-source-reconstruction", "no-human-AT-testing"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ghidra-home", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    result = execute(args.ghidra_home)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(result["qualification"])


if __name__ == "__main__":
    main()
