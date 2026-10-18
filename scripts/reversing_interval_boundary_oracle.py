#!/usr/bin/env python3
"""Independent bounded GNU objdump structural oracle for stripped Ghidra ranges.

The original *symbol-bearing* compiler output is inspected with objdump only
outside Ghidra. This observes instruction boundaries and NOP-only padding;
it does not establish reachability, block ownership, or source equivalence.
"""
import hashlib
import json
import re

MAX_SYMBOL_BYTES = 65536
LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s+(.+?)\s*$')

class BoundaryOracleError(ValueError):
    pass


def parse_objdump_nonnop_ranges(text, symbol, size):
    if type(symbol) is not int or type(size) is not int or symbol < 1 or not 0 < size <= MAX_SYMBOL_BYTES:
        raise BoundaryOracleError('unbounded symbol oracle')
    if not isinstance(text, str) or len(text) > 262144:
        raise BoundaryOracleError('unbounded objdump output')
    # This is intentionally the only symbol name admitted by the fixed fixture.
    header = re.compile(r'^\s*[0-9a-fA-F]+\s+<fixture_target>:\s*$')
    if sum(bool(header.fullmatch(line)) for line in text.splitlines()) != 1:
        raise BoundaryOracleError('missing or ambiguous target disassembly')
    entries = []
    for line in text.splitlines():
        match = LINE.fullmatch(line)
        if not match:
            continue
        addr = int(match[1], 16)
        if addr < symbol or addr >= symbol + size:
            raise BoundaryOracleError('objdump address outside nm symbol')
        nbytes = len(match[2].split())
        asm = match[3].lower()
        padding = bool(re.search(r'\bnop[a-z]*\b', asm))
        if addr + nbytes > symbol + size:
            raise BoundaryOracleError('objdump instruction exceeds nm symbol')
        entries.append((addr, addr+nbytes, padding))
    entries.sort()
    if not entries or entries[0][0] != symbol or entries[-1][1] != symbol + size:
        raise BoundaryOracleError('incomplete objdump symbol coverage')
    if any(a[1] != b[0] for a, b in zip(entries, entries[1:])):
        raise BoundaryOracleError('gap or overlap in objdump decode')
    boundaries = {symbol, symbol + size}
    spans = []
    for a, b, padding in entries:
        boundaries.add(a)
        boundaries.add(b)
        if not padding:
            if spans and spans[-1][1] == a:
                spans[-1] = (spans[-1][0], b)
            else:
                spans.append((a, b))
    if not spans:
        raise BoundaryOracleError('all-padding target has no independent code spans')
    return spans, boundaries


def compare_ghidra_ranges(export, symbol, size, oracle_ranges, boundaries, image_base):
    if not isinstance(export, dict) or set(export) != {'schema','image_base','executable_format','functions'}:
        return {'classification':'INVALID_GHIDRA_EXPORT'}
    if export['schema'] != 'ghidra-function-ranges/v1' or not isinstance(export['functions'], list):
        return {'classification':'INVALID_GHIDRA_EXPORT'}
    if len(export['functions']) > 1024:
        return {'classification':'INVALID_GHIDRA_EXPORT'}
    if (not isinstance(export['image_base'], str) or not export['image_base'].isdigit()
            or int(export['image_base']) != image_base
            or not isinstance(export['executable_format'], str)
            or 'ELF' not in export['executable_format']):
        return {'classification':'INVALID_GHIDRA_EXPORT'}
    selected = [f for f in export['functions'] if isinstance(f, dict) and f.get('entry') == str(symbol)]
    if len(selected) != 1 or set(selected[0]) != {'name','entry','ranges'}:
        return {'classification':'ENTRY_NOT_UNIQUE'}
    ranges = selected[0]['ranges']
    if not isinstance(ranges, list) or not 1 <= len(ranges) <= 32:
        return {'classification':'INVALID_GHIDRA_RANGES'}
    actual=[]
    for r in ranges:
        if not isinstance(r, dict) or set(r) != {'start','end_exclusive'}:
            return {'classification':'INVALID_GHIDRA_RANGES'}
        if not all(isinstance(r[x], str) and re.fullmatch(r'[0-9]+',r[x]) for x in ('start','end_exclusive')):
            return {'classification':'INVALID_GHIDRA_RANGES'}
        a,b=int(r['start']),int(r['end_exclusive'])
        if a >= b:
            return {'classification':'INVALID_GHIDRA_RANGES'}
        actual.append((a,b))
    actual.sort()
    if any(a[1] > b[0] for a,b in zip(actual,actual[1:])):
        return {'classification':'OVERLAPPING_GHIDRA_RANGES'}
    if any(a < symbol or b > symbol+size for a,b in actual):
        cls='OUTSIDE_SYMBOL_ORACLE'
    elif any(a not in boundaries or b not in boundaries for a,b in actual):
        cls='NON_INSTRUCTION_BOUNDARY'
    else:
        cls=None
    matched = sum(max(0,min(b,d)-max(a,c)) for a,b in actual for c,d in oracle_ranges)
    expected = sum(b-a for a,b in oracle_ranges)
    observed = sum(b-a for a,b in actual)
    missing, extra = expected-matched, observed-matched
    if cls is None:
        if actual == oracle_ranges:
            cls='EXACT_OBJDUMP_NONNOP_INTERVALS'
        elif missing == 0 and extra == 0:
            cls='EQUIVALENT_COVERAGE_DIFFERENT_PARTITION'
        elif extra > 0:
            cls='INCLUDES_PADDING_OR_NONORACLE_BYTES'
        else:
            cls='PARTIAL_NONNOP_COVERAGE'
    return {'classification':cls,
            'ghidra_interval_count':len(actual),
            'objdump_nonnop_interval_count':len(oracle_ranges),
            'missing_nonnop_bytes':missing,
            'extra_nonoracle_bytes':extra,
            'symbol_size':size,
            'oracle_sha256':hashlib.sha256(json.dumps(oracle_ranges,separators=(',',':')).encode()).hexdigest(),
            'interpretation':'STRUCTURAL_INSTRUCTION_AND_PADDING_ONLY_NOT_CFG_OR_SEMANTIC_EQUIVALENCE'}
