#!/usr/bin/env python3
"""Fixed public-synthetic x86-64 GDB first-argument intervention oracle.

Only a new disposable native inferior of a known generated *stripped* ELF is
used. Stop at the independently attested function entry, inspect ABI register
RDI, set a bounded alternate first argument, then resume to one separately
attested instruction-island start. No arbitrary user commands or binaries.
A non-hit in a single run does NOT imply unreachable code.
"""
import re

class InterventionError(ValueError):
    pass

# The exact public fixture calls fixture_target(7); allow only these inputs.
ALLOWED_ARGUMENTS = (1, 4, 8, 12, 0, -1)
BASELINE_ARGUMENT = 7
MAX_ISLANDS = 32
MAX_OUTPUT = 131072


def _single_hex_line(output, regex, message):
    values = re.findall(regex, output, re.M)
    if len(values) != 1:
        raise InterventionError("absent/ambiguous " + message)
    return int(values[0], 16)


def _single_decimal_line(output, regex, message):
    values = re.findall(regex, output, re.M)
    if len(values) != 1:
        raise InterventionError("absent/ambiguous " + message)
    return int(values[0])


def parse_intervention_receipt(output, entry_va, target_va, argument):
    """Classify debugger evidence, not code coverage, CFG or source semantics."""
    if not isinstance(output, str) or len(output) > MAX_OUTPUT:
        raise InterventionError("unbounded GDB transcript")
    if not all(type(v) is int and 0 < v < 2**64 for v in (entry_va, target_va)):
        raise InterventionError("invalid fixed x86-64 instruction PC")
    if type(argument) is not int or argument not in ALLOWED_ARGUMENTS:
        raise InterventionError("argument not on bounded qualification allowlist")
    if re.search(
        r"(?:Program received signal|signal SIG|No such process|Cannot insert breakpoint|"
        r"^warning:.*cannot access memory|^Cannot access memory|"
        r"^The program is not being run|^No registers|^Error in sourced command)",
        output, re.I | re.M
    ):
        raise InterventionError("GDB execution error or signal")
    bp1 = _single_hex_line(output, r"^Breakpoint 1 at 0x([0-9a-fA-F]+)\b",
                           "entry breakpoint installed")
    hit1 = _single_hex_line(output, r"^Breakpoint 1, 0x([0-9a-fA-F]+)\b",
                            "entry breakpoint hit")
    marker_pc = _single_hex_line(output, r"^RE_RDI_ENTRY_PC=(0x[0-9a-fA-F]+)$",
                                 "printed entry PC")
    before = _single_decimal_line(output, r"^RE_RDI_BEFORE=(-?[0-9]+)$",
                                  "initial RDI")
    after = _single_decimal_line(output, r"^RE_RDI_AFTER=(-?[0-9]+)$",
                                 "modified RDI")
    if (bp1, hit1, marker_pc, before, after) != (
        entry_va, entry_va, entry_va, BASELINE_ARGUMENT, argument
    ):
        raise InterventionError("entry breakpoint or RDI intervention not attested")
    # Establish temporal provenance: a PC hit preceding the register write
    # must never be accepted as execution *after* the intervention.
    ordered = [
        re.search(r"^Breakpoint 1 at 0x", output, re.M).start(),
        re.search(r"^Breakpoint 1, 0x", output, re.M).start(),
        re.search(r"^RE_RDI_ENTRY_PC=", output, re.M).start(),
        re.search(r"^RE_RDI_BEFORE=", output, re.M).start(),
        re.search(r"^RE_RDI_AFTER=", output, re.M).start(),
    ]
    if any(a >= b for a, b in zip(ordered, ordered[1:])):
        raise InterventionError("GDB entry/RDI evidence occurred out of order")
    after_pos = ordered[-1]
    if target_va == entry_va:
        if re.search(r"^Breakpoint 2(?: at|,)", output, re.M):
            raise InterventionError("duplicate breakpoint at original entry")
        return "ENTRY_PC_OBSERVED_AND_RDI_ATTESTED"

    bp2 = _single_hex_line(output, r"^Breakpoint 2 at 0x([0-9a-fA-F]+)\b",
                           "island breakpoint installed")
    if bp2 != target_va:
        raise InterventionError("island breakpoint installed at wrong PC")
    # One bounded native inferior: a target stop and a normal exit are
    # contradictory terminal observations, not two interchangeable successes.
    if re.search(r"^\[Inferior [0-9]+ \(process [0-9]+\) exited (?:with|due to)",
                 output, re.M | re.I):
        raise InterventionError("inferior terminated abnormally")
    exits = list(re.finditer(
        r"^\[Inferior [0-9]+ \(process [0-9]+\) exited normally\]$", output, re.M))
    if len(exits) > 1:
        raise InterventionError("ambiguous multiple normal exits")
    target_hits = [int(v, 16) for v in re.findall(
        r"^Breakpoint 2, 0x([0-9a-fA-F]+)\b", output, re.M)]
    if target_hits:
        if exits:
            raise InterventionError("contradictory target hit and inferior exit")
        if target_hits != [target_va]:
            raise InterventionError("unexpected island hit PC or repeated hit")
        target_pos = re.search(r"^Breakpoint 2, 0x", output, re.M).start()
        if target_pos <= after_pos:
            raise InterventionError("island PC hit before attested RDI intervention")
        return "BREAKPOINT_OBSERVED_AFTER_RDI_INTERVENTION"
    clean_exit = exits[0] if exits else None
    if clean_exit:
        if clean_exit.start() <= after_pos:
            raise InterventionError("inferior exited before attested RDI intervention")
        return "NOT_OBSERVED_IN_THIS_INTERVENED_RUN"
    raise InterventionError("no authenticated hit or inferior normal exit")


def observe_intervened_islands(stripped, entry_va, intervals, run_program):
    """New GDB process per (argument, interval) with fixed commands only."""
    if not isinstance(intervals, list) or not 1 <= len(intervals) <= MAX_ISLANDS:
        raise InterventionError("empty or unbounded independent intervals")
    if type(entry_va) is not int or entry_va <= 0 or entry_va >= 2**64:
        raise InterventionError("invalid oracle entry")
    seen = set()
    for span in intervals:
        if (not isinstance(span, (tuple, list)) or len(span) != 2
                or any(type(v) is not int for v in span)
                or not 0 < span[0] < span[1] <= 2**64
                or span[0] in seen):
            raise InterventionError("invalid or duplicated independent interval")
        seen.add(span[0])
    if entry_va != intervals[0][0]:
        raise InterventionError("source-known function entry not first interval")
    reports = []
    for n in ALLOWED_ARGUMENTS:
        per_island = []
        for i, (target, _end) in enumerate(intervals):
            argv = ["gdb", "--batch", "--nx", "--quiet", str(stripped),
                    "-ex", "set pagination off",
                    "-ex", "break *0x%x" % entry_va]
            if target != entry_va:
                argv += ["-ex", "break *0x%x" % target]
            argv += [
                "-ex", "run",
                "-ex", 'printf "RE_RDI_ENTRY_PC=%p\\n", $pc',
                "-ex", 'printf "RE_RDI_BEFORE=%ld\\n", $rdi',
                "-ex", "set $rdi = %d" % n,
                "-ex", 'printf "RE_RDI_AFTER=%ld\\n", $rdi',
            ]
            if target != entry_va:
                argv += ["-ex", "continue"]
            output = run_program(argv, timeout=35)
            per_island.append({
                "interval_index": i,
                "target_delta_from_entry": target - entry_va,
                "status": parse_intervention_receipt(output, entry_va, target, n)
            })
        observed = [x["interval_index"] for x in per_island
                    if x["status"] in (
                        "ENTRY_PC_OBSERVED_AND_RDI_ATTESTED",
                        "BREAKPOINT_OBSERVED_AFTER_RDI_INTERVENTION")]
        nonhit = [x["interval_index"] for x in per_island
                  if x["status"] == "NOT_OBSERVED_IN_THIS_INTERVENED_RUN"]
        reports.append({
            "argument_n": n, "interval_count": len(per_island),
            "observed_indices": observed, "not_observed_indices": nonhit,
            "statuses": per_island
        })
    return {
        "status": "RDI_INTERVENTION_ISLAND_SAMPLES_MEASURED",
        "baseline_argument_n": BASELINE_ARGUMENT,
        "abi": "X86_64_SYSV_FIRST_ARGUMENT_RDI",
        "arguments": reports,
        "interpretation":
            "ENTRY_PC_AND_RDI_ATTESTED_PER_FRESH_GDB_RUN_ONE_ISLAND_START_ONLY"
            "_NOT_ALL_PATHS_OR_REACHABILITY"
    }
