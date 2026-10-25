#!/usr/bin/env python3
"""Second native PC measurement of only the existing generated public x86-64 ELF.

This is an import-only fixed-fixture helper, NOT an arbitrary executable CLI.
It rehashes the actual stripped binary and launches fresh read-only GDB
processes for n=0/n=1. A second GDB on the same host is NOT a sealed
independent evaluator, and GDB console remains unsuitable for hostile stdout.
"""
from hashlib import sha256
from pathlib import Path
import re

LIMIT = 131072
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
EXPECTED_INPUTS = (0, 1)
WITNESS = "NATIVE_PC_WITNESS"
NONHIT = "NOT_OBSERVED_SAMPLE"

class ReplayError(ValueError):
    pass


def _one(text, pattern, label):
    matches = list(re.finditer(pattern, text, re.M))
    if len(matches) != 1:
        raise ReplayError("missing or duplicate " + label)
    return matches[0]


def parse_replay(output, entry_va, target_va, n):
    """Evidence classification for a fixed, no-stdout inferior only."""
    if not isinstance(output, str) or len(output) > LIMIT:
        raise ReplayError("invalid bounded GDB transcript")
    if (type(n) is not int or n not in EXPECTED_INPUTS or
            any(type(v) is not int or not 0 < v < 2**64
                for v in (entry_va, target_va)) or entry_va >= target_va):
        raise ReplayError("invalid fixed SysV replay arguments")
    if re.search(
            r"(?:Program received signal|signal SIG|Cannot insert breakpoint|"
            r"No such process|^warning:.*cannot access memory|"
            r"^Cannot access memory|^The program is not being run|"
            r"^No registers|^Error in sourced command|"
            r"^\[Inferior [0-9]+ \(process [0-9]+\) exited (?:with|due to))",
            output, re.M | re.I):
        raise ReplayError("GDB reported an invalid or abnormal inferior")
    entry_set = _one(output, r"^Breakpoint 1 at 0x([0-9a-fA-F]+)\b", "entry breakpoint set")
    target_set = _one(output, r"^Breakpoint 2 at 0x([0-9a-fA-F]+)\b", "target breakpoint set")
    entry_hit = _one(output, r"^Breakpoint 1, 0x([0-9a-fA-F]+)\b", "entry breakpoint hit")
    pc = _one(output, r"^RVR_ENTRY_PC=0x([0-9a-fA-F]+)$", "entry program counter")
    before = _one(output, r"^RVR_BEFORE=(-?[0-9]+)$", "initial RDI")
    after = _one(output, r"^RVR_AFTER=(-?[0-9]+)$", "modified RDI")
    if (int(entry_set[1], 16), int(target_set[1], 16),
            int(entry_hit[1], 16), int(pc[1], 16),
            int(before[1]), int(after[1])) != (
            entry_va, target_va, entry_va, entry_va, 7, n):
        raise ReplayError("PC, breakpoint address or SysV-RDI values differ")
    seq = (entry_set, target_set, entry_hit, pc, before, after)
    if any(x.start() >= y.start() for x, y in zip(seq, seq[1:])):
        raise ReplayError("GDB setup/intervention temporal order invalid")
    hits = list(re.finditer(r"^Breakpoint 2, 0x([0-9a-fA-F]+)\b", output, re.M))
    exits = list(re.finditer(
        r"^\[Inferior [0-9]+ \(process [0-9]+\) exited normally\]$",
        output, re.M))
    if hits and exits:
        raise ReplayError("conflicting target hit and normal inferior exit")
    if len(hits) > 1 or len(exits) > 1:
        raise ReplayError("ambiguous repeated terminal observation")
    if hits:
        if hits[0].start() <= after.end() or int(hits[0][1], 16) != target_va:
            raise ReplayError("target PC not hit after signed RDI change")
        return WITNESS
    if exits:
        if exits[0].start() <= after.end():
            raise ReplayError("normal exit before signed RDI change")
        return NONHIT
    raise ReplayError("no authenticated target hit or normal inferior exit")


def replay_fixed_stripped(binary, entry_va, target_va, image_base, expected_sha256, run_program):
    """Called before existing producer's temporary fixture is deleted.

    Caller must create the exact hardcoded public synthetic, establish its
    known-original GNU function/target and independently verify the Ghidra
    and objdump interval geometry. No user-supplied binary/replay CLI exists.
    """
    if not isinstance(binary, Path) or binary.is_symlink() or not binary.is_file():
        raise ReplayError("missing ordinary temporary synthetic ELF")
    if (binary.stat().st_size == 0 or binary.stat().st_size > MAX_FIXTURE_BYTES
            or binary.open("rb").read(6) != b"\x7fELF\x02\x01"):
        raise ReplayError("wrong or oversized public x86-64 ELF fixture")
    if (not isinstance(expected_sha256, str) or
            re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None or
            expected_sha256 == "0" * 64):
        raise ReplayError("invalid expected actual stripped digest")
    if (type(image_base) is not int or type(entry_va) is not int or
            type(target_va) is not int or
            not 0 < image_base <= entry_va < target_va < 2**64):
        raise ReplayError("invalid bounded image or source function target")
    actual = sha256(binary.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise ReplayError("actual stripped bytes differ from produced receipt")
    cases = []
    for n in EXPECTED_INPUTS:
        argv = [
            "gdb", "--batch", "--nx", "--quiet", str(binary),
            "-ex", "set pagination off",
            "-ex", "break *0x%x" % entry_va,
            "-ex", "break *0x%x" % target_va,
            "-ex", "run",
            "-ex", 'printf "RVR_ENTRY_PC=%p\\n", $pc',
            "-ex", 'printf "RVR_BEFORE=%ld\\n", $rdi',
            "-ex", "set $rdi = %d" % n,
            "-ex", 'printf "RVR_AFTER=%ld\\n", $rdi',
            "-ex", "continue",
        ]
        output = run_program(argv, timeout=35)
        observed = parse_replay(output, entry_va, target_va, n)
        if sha256(binary.read_bytes()).hexdigest() != actual:
            raise ReplayError("ELF bytes changed between native replay runs")
        cases.append({
            "input_n": n, "target_rva": target_va-image_base,
            "verdict": observed,
        })
    return {
        "schema": "reversing-native-second-replay/v1",
        "scope": "PUBLIC_FIXED_NO_STDOUT_SYNTHETIC_ONLY",
        "independence": "FRESH_GDB_PROCESSES_SAME_HOST_SAME_INSTRUMENTATION",
        "artifact_sha256": actual,
        "entry_rva": entry_va-image_base,
        "target_rva": target_va-image_base,
        "cases": cases,
    }
