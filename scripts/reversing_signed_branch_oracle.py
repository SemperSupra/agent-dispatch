#!/usr/bin/env python3
"""Byte-grounded direct-branch oracle for one bounded public x86-64 ELF.

Uses GNU objdump of the known-symbol original, not the stripped input to
Ghidra. Signed-branch target identity is a static claim; native GDB supplies
a separate execution witness. Do not infer reachability from a static edge.
"""
import re

MAX_OUTPUT = 262144
LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s+(.+?)\s*$')

class SignedBranchError(ValueError):
    pass


def assess_signed_early_exit(disasm, entry, symbol_size, intervals):
    if not isinstance(disasm, str) or len(disasm) > MAX_OUTPUT:
        raise SignedBranchError("unbounded disassembly")
    if type(entry) is not int or type(symbol_size) is not int or not 0 < entry < 2**64 or not 0 < symbol_size <= 65536:
        raise SignedBranchError("invalid bounded symbol")
    if (not isinstance(intervals, list) or len(intervals) != 4 or
            any(not isinstance(p, tuple) or len(p) != 2 or
                any(type(x) is not int for x in p) for p in intervals)):
        return {"status": "INCONCLUSIVE_NOT_FOUR_CODE_INTERVALS"}
    if intervals != sorted(intervals) or any(not entry <= a < b <= entry+symbol_size for a,b in intervals):
        raise SignedBranchError("invalid independent interval bounds")
    header = re.compile(r'^\s*[0-9a-fA-F]+\s+<fixture_target>:\s*$')
    if sum(bool(header.fullmatch(x)) for x in disasm.splitlines()) != 1:
        raise SignedBranchError("missing or ambiguous fixed fixture heading")
    rows = []
    for line in disasm.splitlines():
        m = LINE.fullmatch(line)
        if m is None:
            continue
        pc = int(m[1], 16)
        if not entry <= pc < entry+symbol_size:
            raise SignedBranchError("decoded instruction outside nm symbol")
        rows.append((pc, bytes.fromhex(m[2]), m[3].strip().lower()))
    rows.sort()
    if not rows or rows[0][0] != entry:
        return {"status":"INCONCLUSIVE_ENTRY_NOT_DECODED"}
    # Do not require a particular instruction at the first byte: GCC versions
    # can safely move register setup before the early conditional branch.
    jles = [(i,p,b,a) for i,(p,b,a) in enumerate(rows)
            if re.match(r'^jle\s+', a) or b[:1]==b'\x7e' or b[:2]==b'\x0f\x8e']
    if len(jles) != 1:
        return {"status":"INCONCLUSIVE_JLE_NOT_UNIQUE"}
    i, pc, data, asm = jles[0]
    if not re.match(r'^jle\s+',asm):
        return {"status":"INCONCLUSIVE_MNEMONIC_BYTE_DISAGREEMENT"}
    if len(data)==2 and data[0]==0x7e:
        rel = int.from_bytes(data[1:],"little",signed=True)
    elif len(data)==6 and data[:2]==b'\x0f\x8e':
        rel = int.from_bytes(data[2:],"little",signed=True)
    else:
        return {"status":"INCONCLUSIVE_NOT_SIGNED_JLE_BYTES"}
    target = pc+len(data)+rel
    rendered = re.match(r'^jle\s+([0-9a-f]+)(?:\s|$)', asm)
    if rendered is None or int(rendered[1],16)!=target:
        raise SignedBranchError("objdump target disagrees with encoded displacement")
    if not entry<=target<entry+symbol_size:
        raise SignedBranchError("branch target beyond bounded function")
    if target!=intervals[3][0]:
        return {"status":"INCONCLUSIVE_TARGET_NOT_FOURTH_ISLAND",
                "decoded_target_rva":target-entry}
    prev = rows[i-1] if i>0 else None
    tested_rdi_immediately_before=bool(
        prev is not None and prev[0]+len(prev[1])==pc and
        prev[1]==b'\x48\x85\xff' and
        re.match(r'^test\s+%rdi,%rdi(?:\s|$)',prev[2]))
    return {
        "status":"SIGNED_JLE_DIRECT_EDGE_TO_ISLAND_3",
        "source_register_if_tested":"RDI" if tested_rdi_immediately_before else "UNKNOWN",
        "rdi_test_immediately_precedes":tested_rdi_immediately_before,
        "width_bits":64,
        "predicate":"signed_flags_le_zero_at_jle",
        "branch_pc_rva":pc-entry,
        "target_rva":target-entry,
        "interval_index":3,
        "instruction_bytes_hex":data.hex(),
        "interpretation":"STATIC_BYTE_DERIVED_EDGE_NOT_INPUT_FEASIBILITY_OR_NATIVE_EXECUTION"
    }
