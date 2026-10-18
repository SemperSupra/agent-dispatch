#!/usr/bin/env python3
"""Native ELF + Ghidra headless + GDB triangulation on fixed public C fixture.

Only executes a locally generated no-network program. No arbitrary target,
private binary, firmware, endpoint, or Ghidra script can be supplied by a caller.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from hashlib import sha256

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "scripts" / "reversing_native_elf_probe.py"
spec = importlib.util.spec_from_file_location("native_reversing_elf", NATIVE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
MAX_EXPORT = 2 * 1024 * 1024


class GhidraOracleError(ValueError):
    pass


def parse_export(raw, symbol, length, image_base):
    """Require Ghidra independently report the exact named ELF symbol and body."""
    if not isinstance(raw, dict) or set(raw) != {"schema", "image_base", "executable_format", "functions"}:
        raise GhidraOracleError("unexpected export envelope")
    if raw["schema"] != "ghidra-function-ranges/v1":
        raise GhidraOracleError("wrong export version")
    if not isinstance(raw["functions"], list) or len(raw["functions"]) > 1024:
        raise GhidraOracleError("unbounded function list")
    if not isinstance(raw["image_base"], str) or not raw["image_base"].isdigit():
        raise GhidraOracleError("invalid image-base")
    if not isinstance(raw["executable_format"], str) or "ELF" not in raw["executable_format"]:
        raise GhidraOracleError("program is not ELF")
    candidates = [f for f in raw["functions"] if isinstance(f, dict) and f.get("name") == native.TARGET]
    if len(candidates) != 1:
        raise GhidraOracleError("expected one independently extracted target")
    f = candidates[0]
    if set(f) != {"name", "entry", "ranges"} or not isinstance(f["entry"], str) or not f["entry"].isdigit():
        raise GhidraOracleError("invalid Ghidra function")
    if int(f["entry"]) != symbol:
        raise GhidraOracleError("Ghidra symbol entry disagrees with independent nm")
    if not isinstance(f["ranges"], list) or len(f["ranges"]) != 1:
        raise GhidraOracleError("discontiguous/ambiguous function unsupported by v1")
    interval = f["ranges"][0]
    if not isinstance(interval, dict) or set(interval) != {"start", "end_exclusive"}:
        raise GhidraOracleError("invalid function interval")
    if any(not isinstance(interval[k], str) or not interval[k].isdigit() for k in ("start", "end_exclusive")):
        raise GhidraOracleError("invalid function interval offset")
    start, end = int(interval["start"]), int(interval["end_exclusive"])
    if not 0 <= start <= symbol < end <= 2**64 - 1:
        raise GhidraOracleError("Ghidra body does not contain independently measured entry")
    if start != symbol or end > symbol + length:
        raise GhidraOracleError("Ghidra body expands beyond independent nm symbol")
    if not image_base <= start < end:
        raise GhidraOracleError("Ghidra body does not belong to ELF load image")
    return {"id": "ghidra_target", "rva": start - image_base, "size": end - start}


def run_probe(ghidra_home):
    analyze = Path(ghidra_home).resolve() / "support" / "analyzeHeadless"
    if not analyze.is_file():
        raise GhidraOracleError("Ghidra analyzeHeadless absent")
    for tool in ("gcc", "nm", "readelf", "gdb"):
        if not shutil.which(tool):
            raise GhidraOracleError(tool + " missing")
    with tempfile.TemporaryDirectory(prefix="ghidra-triangulation-") as dirname:
        d = Path(dirname)
        source, binary = d / "public-fixture.c", d / "public-fixture"
        source.write_text(native.FIXTURE, encoding="utf-8")
        native.run(["gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-fno-omit-frame-pointer",
                    "-Wall", "-Wextra", "-o", str(binary), str(source)])
        native.run([str(binary)], timeout=5)
        symbol, size = native.parse_symbol(native.run(["nm", "-n", "-S", "--defined-only", str(binary)]))
        base, total = native.parse_image(native.run(["readelf", "-W", "-l", str(binary)]))
        binary_hash = sha256(binary.read_bytes()).hexdigest()
        if not base <= symbol < symbol + size <= base + total:
            raise GhidraOracleError("independent symbol does not fit the ELF load map")
        export = d / "ghidra-functions.json"
        (d / "projects").mkdir(mode=0o700)
        script_dir = ROOT / "scripts" / "ghidra"
        proc = subprocess.run([str(analyze), str(d / "projects"), "reversing-fixture",
                               "-import", str(binary), "-scriptPath", str(script_dir),
                               "-postScript", "ReversingExportFunctions.java", str(export),
                               "-max-cpu", "2", "-analysisTimeoutPerFile", "120",
                               "-deleteProject"], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, check=False, timeout=240)
        if proc.returncode != 0 or not export.is_file() or export.stat().st_size > MAX_EXPORT:
            # This fixture contains no private input. Retain only bounded tool
            # diagnostics, never full headless logs or intermediate binary bytes.
            detail = "\n".join(
                line[:220] for line in (proc.stdout + "\n" + proc.stderr).splitlines()
                if any(word in line.lower() for word in
                       ("error", "exception", "failed", "not found", "script"))
            )[-2000:]
            raise GhidraOracleError(
                "Ghidra export incomplete (rc=" + str(proc.returncode) +
                ", file_present=" + str(export.is_file()) + "); " + detail)
        function = parse_export(json.loads(export.read_text(encoding="utf-8")), symbol, size, base)
        gdb_output = native.run(["gdb", "--batch", "--nx", "--quiet", str(binary),
                                "-ex", "set pagination off", "-ex", "break *fixture_target",
                                "-ex", "run", "-ex", 'printf "RE_PC=%p\\n", $pc',
                                "-ex", "continue"], timeout=35)
        observed = native.parse_gdb_pc(gdb_output)
        if observed != symbol:
            raise GhidraOracleError("raw instruction-entry breakpoint not reached")
        document = {
            "schema": native.CORR.INPUT_SCHEMA, "run_id": "generated-ghidra-native-001",
            "mode": "synthetic", "artifact_sha256": binary_hash,
            "functions": [function],
            "module_loads": [{"id": "main-executable", "artifact_sha256": binary_hash,
                              "base_va": base, "size": total}],
            "events": [{"id": "gdb-entry", "kind": "instruction", "sensor": "native-gdb",
                        "vantage": "guest", "run_id": "generated-ghidra-native-001",
                        "time_domain": "debugger-session", "module_load_id": "main-executable",
                        "va": observed}],
        }
        correlated = native.CORR.correlate(document)
        if len(correlated["matched_instructions"]) != 1 or correlated["unresolved_observations"]:
            raise GhidraOracleError("Ghidra and native debugger function identity mismatch")
        if correlated["matched_instructions"][0]["function_id"] != "ghidra_target":
            raise GhidraOracleError("function mapping mismatch")
        return {
            "schema": "reversing-ghidra-gdb-synthetic-receipt/v1",
            "qualification": "NATIVE_SYNTHETIC_GHIDRA_GDB_CORRELATION_PASS",
            "binary_sha256": binary_hash,
            "ghidra_function_count_accepted": 1,
            "ghidra_function_rva": function["rva"],
            "nm_symbol_rva": symbol - base,
            "gdb_breakpoint_rva": observed - base,
            "input_sha256": correlated["input_sha256"],
            "limits": ["generated-public-ELF-with-symbols", "not-stripped-source-recovery",
                       "not-windows-or-android", "not-kvm-qemu-or-hyperv", "not-UI-accessibility",
                       "no-external-sensors", "no-general-behavioral-equivalence-proof"],
        }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ghidra-home", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = run_probe(args.ghidra_home)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(result["qualification"])


if __name__ == "__main__":
    main()
