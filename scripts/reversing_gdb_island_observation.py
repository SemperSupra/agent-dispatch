#!/usr/bin/env python3
"""Typed native GDB function-island observation, fixed synthetic stripped ELF only.

An observed breakpoint establishes that a specific address executed in this
run. NOT_OBSERVED never means unreachable, nor does a hit prove an entire
function island, CFG, or behavior.
"""
import re

class IslandObservationError(ValueError):
    pass

_GDB_BREAK_SET = re.compile(r'^Breakpoint 1 at 0x([0-9a-fA-F]+)\b', re.MULTILINE)
_GDB_BREAK_HIT = re.compile(r'^Breakpoint 1, 0x([0-9a-fA-F]+)\b', re.MULTILINE)


def classify_gdb_single_breakpoint(output, requested_va):
    if not isinstance(output, str) or len(output) > 131072:
        raise IslandObservationError('unbounded debugger receipt')
    if type(requested_va) is not int or not 0 <= requested_va < 2**64:
        raise IslandObservationError('invalid requested VA')
    installed = [int(x, 16) for x in _GDB_BREAK_SET.findall(output)]
    if installed != [requested_va]:
        raise IslandObservationError('breakpoint installation lacks exact address')
    # A signal or debugger failure cannot qualify as a normal non-hit, even
    # when another line in the combined GDB transcript mentions clean exit.
    if re.search(r'(?:signal SIG|Program received signal|No such process|^Cannot insert breakpoint|^warning:.*cannot access memory)', output, re.I | re.M):
        raise IslandObservationError('debugger reports signal or invalid execution')
    hits = [int(x, 16) for x in _GDB_BREAK_HIT.findall(output)]
    if hits:
        if hits != [requested_va]:
            raise IslandObservationError('breakpoint hit does not match requested PC')
        return 'BREAKPOINT_OBSERVED'
    if re.search(r'^\[Inferior [0-9]+ \(process [0-9]+\) exited normally\]$', output, re.M):
        return 'NOT_OBSERVED_IN_THIS_RUN'
    raise IslandObservationError('neither breakpoint hit nor normal process completion')


def probe_static_intervals(stripped, intervals, run_program):
    """One fresh ordinary native GDB inferior for each independent interval start."""
    if not isinstance(intervals, list) or not 1 <= len(intervals) <= 32:
        raise IslandObservationError('invalid bounded interval census')
    seen = set()
    observations = []
    for i, interval in enumerate(intervals):
        if (not isinstance(interval, (tuple, list)) or len(interval) != 2
                or any(type(x) is not int for x in interval)):
            raise IslandObservationError('invalid interval')
        start, end = interval
        if not 0 <= start < end <= 2**64 or start in seen:
            raise IslandObservationError('invalid or duplicated interval start')
        seen.add(start)
        text = run_program(
            ['gdb', '--batch', '--nx', '--quiet', str(stripped),
             '-ex', 'set pagination off', '-ex', 'break *0x%x' % start,
             '-ex', 'run'], timeout=35)
        status = classify_gdb_single_breakpoint(text, start)
        observations.append({'interval_index': i, 'status': status})
    return {
        'status': 'NATIVE_GDB_ISLAND_SAMPLES_MEASURED',
        'interval_count': len(observations),
        'observed_count': sum(x['status'] == 'BREAKPOINT_OBSERVED' for x in observations),
        'not_observed_count': sum(x['status'] == 'NOT_OBSERVED_IN_THIS_RUN' for x in observations),
        'intervals': observations,
        'interpretation': 'ONE_ADDRESS_PER_INTERVAL_PER_FRESH_RUN_NOT_ALL_PATHS_OR_REACHABILITY'
    }
