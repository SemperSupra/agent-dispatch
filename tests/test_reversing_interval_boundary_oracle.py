"""Adversarial independent instruction-boundary oracle, no Ghidra dependency."""
import copy
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "scripts/reversing_interval_boundary_oracle.py"
SPEC = importlib.util.spec_from_file_location("reversing_boundary_oracle", P)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
START = 0x401000
RAW = """/tmp/original: file format elf64-x86-64
Disassembly of section .text:
0000000000401000 <fixture_target>:
  401000: 55     push %rbp
  401001: c3     ret
  401002: 0f 1f 00      nopl (%rax)
  401005: c3     ret
"""


def export(pairs):
    return {"schema": "ghidra-function-ranges/v1", "image_base": str(0x400000),
            "executable_format": "ELF",
            "functions": [{"entry": str(START), "name": "FUN",
                           "ranges": [{"start": str(a), "end_exclusive": str(b)}
                                      for a, b in pairs]}]}


class IndependentOracleTests(unittest.TestCase):
    def setUp(self):
        self.spans, self.bounds = M.parse_objdump_nonnop_ranges(RAW, START, 6)

    def check(self, pairs):
        return M.compare_ghidra_ranges(export(pairs), START, 6, self.spans, self.bounds, 0x400000)

    def test_exact_discontiguous_nonnop(self):
        self.assertEqual(self.spans, [(START, START+2), (START+5, START+6)])
        self.assertEqual(self.check(self.spans)["classification"], "EXACT_OBJDUMP_NONNOP_INTERVALS")

    def test_missing_code_is_partial(self):
        result = self.check([(START, START+2)])
        self.assertEqual(result["classification"], "PARTIAL_NONNOP_COVERAGE")
        self.assertEqual(result["missing_nonnop_bytes"], 1)

    def test_included_nop_is_not_promoted(self):
        result = self.check([(START, START+6)])
        self.assertEqual(result["classification"], "INCLUDES_PADDING_OR_NONORACLE_BYTES")
        self.assertEqual(result["extra_nonoracle_bytes"], 3)

    def test_outside_nm_symbol(self):
        self.assertEqual(self.check([(START, START+7)])["classification"], "OUTSIDE_SYMBOL_ORACLE")

    def test_overlap_rejected(self):
        self.assertEqual(self.check([(START, START+2), (START+1, START+6)])["classification"],
                         "OVERLAPPING_GHIDRA_RANGES")

    def test_middle_of_instruction_fails(self):
        self.assertEqual(self.check([(START+3, START+6)])["classification"],
                         "NON_INSTRUCTION_BOUNDARY")

    def test_gap_or_unbounded_symbol_fails(self):
        with self.assertRaises(M.BoundaryOracleError):
            M.parse_objdump_nonnop_ranges(RAW.replace("  401001: c3     ret", ""), START, 6)
        with self.assertRaises(M.BoundaryOracleError):
            M.parse_objdump_nonnop_ranges(RAW, START, 65537)

    def test_only_nop_fails(self):
        raw = "0000000000401000 <fixture_target>:\n 401000: 90 nop\n"
        with self.assertRaises(M.BoundaryOracleError):
            M.parse_objdump_nonnop_ranges(raw, START, 1)

    def test_wrong_image_base_and_non_elf_cannot_pass(self):
        for key, value in (("image_base", str(0x500000)), ("executable_format", "PE")):
            with self.subTest(key=key):
                x = export(self.spans)
                x[key] = value
                r = M.compare_ghidra_ranges(x, START, 6, self.spans, self.bounds, 0x400000)
                self.assertEqual(r["classification"], "INVALID_GHIDRA_EXPORT")

    def test_duplicate_entry_is_unknown(self):
        x = export(self.spans)
        x["functions"].append(copy.deepcopy(x["functions"][0]))
        self.assertEqual(M.compare_ghidra_ranges(x, START, 6, self.spans, self.bounds)["classification"],
                         "ENTRY_NOT_UNIQUE")


if __name__ == "__main__":
    unittest.main()
