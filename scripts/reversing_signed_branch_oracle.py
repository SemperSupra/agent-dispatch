#!/usr/bin/env python3
"""Bounded x86-64 signed branch-target oracle for one public GCC synthetic ELF.

Independent GNU objdump of source-known original (not fed to Ghidra), decoded
branch bytes and actual stripped Ghidra AddressSet must agree. This is a
branch-edge hypothesis; execution requires a separate native GDB witness.
"""
import re

MAX_OUTPUT = 262144
LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*)\s+(.+?)\s*$')

class SignedBranchError(ValueError):
    pass


def assess_signed_early_exit(disasm, entry, symbol_size, intervals):
    """Return exact byte-derived signed-branch edge or a typed inconclusive state."""
    if not isinstance(disasm, str) or len(disasm) > MAX_OUTPUT:
        raise SignedBranchError("unbounded disassembly")
    if type(entry) is not int or type(symbol_size) is not int or not 0 < entry < 2**64 or not 0 < symbol_size <= 65536:
        raise SignedBranchError("invalid bounded nm symbol")
    if (not isinstance(intervals, list) or len(intervals) != 4 or
            any(not isinstance(p, tuple) or len(p) != 2 or
                any(type(x) is not int for x in p) for p in intervals)):
        return {"status": "INCONCLUSIVE_NOT_FOUR_CODE_INTERVALS"}
    if any(not entry <= a < b <= entry + symbol_size for a, b in intervals):
        raise SignedBranchError("independent code ranges beyond symbol")
    if intervals != sorted(intervals):
        raise SignedBranchError("unordered independent code intervals")
    header = re.compile(r'^\s*[0-9a-fA-F]+\s+<fixture_target>:\s*$')
    if sum(bool(header.fullmatch(line)) for line in disasm.splitlines()) != 1:
        raise SignedBranchError("ambiguous source-known symbol heading")
    rows = []
    for line in disasm.splitlines():
        m = LINE.fullmatch(line)
        if m is not None:
            addr = int(m[1], 16)
            if not entry <= addr < entry + symbol_size:
                raise SignedBranchError("instruction outside bounded symbol")
            rows.append((addr, bytes.fromhex(m[2]), m[3].strip().lower()))
    rows.sort()
    if len(rows) < 2 or rows[0][0] != entry:
        return {"status": "INCONCLUSIVE_NO_ENTRY_INSTRUCTIONS"}
    first, second = rows[:2]
    # x86-64 test %rdi,%rdi followed by signed jle rel8 or rel32.
    if first[1] != b'\x48\x85\xff' or not re.match(r'^test\s+%rdi,%rdi(?:\s|$)', first[2]):
        return {"status": "INCONCLUSIVE_ENTRY_FLAGS_NOT_TEST_RDI"}
    if second[0] != entry + 3:
        return {"status": "INCONCLUSIVE_NONADJACENT_BRANCH"}
    if second[1][:1] == b'\x7e' and len(second[1]) == 2:
        offset = int.from_bytes(second[1][1:2], "little", signed=True)
    elif second[1][:2] == b'\x0f\x8e' and len(second[1]) == 6:
        offset = int.from_bytes(second[1][2:6], "little", signed=True)
    else:
        return {"status": "INCONCLUSIVE_NOT_SIGNED_JLE_BYTES"}
    if not re.match(r'^jle\s+', second[2]):
        return {"status": "INCONCLUSIVE_MNEMONIC_BYTE_DISAGREEMENT"}
    target = second[0] + len(second[1]) + offset
    rendered = re.match(r'^jle\s+([0-9a-f]+)(?:\s|$)', second[2])
    if rendered is None or int(rendered[1], 16) != target:
        raise SignedBranchError("objdump rendered target contradicts branch bytes")
    if not entry <= target < entry + symbol_size:
        raise SignedBranchError("decoded branch escapes source-known symbol")
    index = next((i for i, (a,b) in enumerate(intervals) if a == target), None)
    if index != 3:
        return {"status": "INCONCLUSIVE_TARGET_NOT_FOURTH_ISLAND",
                "decoded_target_rva": target - entry}
    return {
        "status": "SIGNED_JLE_DIRECT_EDGE_TO_ISLAND_3",
        "source_register": "RDI", "width_bits": 64,
        "predicate": "signed_n_le_zero_after_test_rdi_rdi",
        "entry_branch_rva": second[0]-entry,
        "target_rva": target-entry,
        "interval_index": 3,
        "instruction_bytes_hex": second[1].hex(),
        "interpretation": "STATIC_BYTE_DERIVED_DIRECT_EDGE_NOT_NATIVE_EXECUTION"
    }
