"""Adversarial byte-grounded synthetic signed entry-branch tests (no runtime)."""
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "scripts/reversing_signed_branch_oracle.py"
SPEC = importlib.util.spec_from_file_location("branch_oracle", P)
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
ENTRY = 0x401000
INTERVALS = [(ENTRY, ENTRY+0x16), (ENTRY+0x20,ENTRY+0x52),
             (ENTRY+0x58,ENTRY+0x61), (ENTRY+0x68,ENTRY+0x6f)]

def disasm(test="48 85 ff", branch="7e 63", target="401068", mnemonic="jle"):
    return (f"0000000000401000 <fixture_target>:\n"
            f"  401000: {test}    test %rdi,%rdi\n"
            f"  401003: {branch}    {mnemonic} {target} <fixture_target+0x68>\n")

class SignedEntryBranchTests(unittest.TestCase):
    def test_signed_short_edge_to_fourth_island(self):
        r=B.assess_signed_early_exit(disasm(), ENTRY, 0x6f, INTERVALS)
        self.assertEqual(r["status"], "SIGNED_JLE_DIRECT_EDGE_TO_ISLAND_3")
        self.assertEqual(r["interval_index"], 3)
        self.assertEqual(r["target_rva"], 0x68)
        self.assertEqual(r["branch_pc_rva"], 3)
        self.assertTrue(r["rdi_test_immediately_precedes"])
        self.assertEqual(r["instruction_bytes_hex"], "7e63")
        self.assertEqual(r["predicate"], "signed_flags_le_zero_at_jle")

    def test_opcode_change_fails_closed(self):
        for encoded in ("7f 63", "76 63", "74 63", "eb 63"):
            with self.subTest(encoded=encoded):
                self.assertEqual(B.assess_signed_early_exit(
                    disasm(branch=encoded), ENTRY, 0x6f, INTERVALS)["status"],
                    "INCONCLUSIVE_NOT_SIGNED_JLE_BYTES")

    def test_opcode_and_mnemonic_disagree(self):
        r=B.assess_signed_early_exit(disasm(mnemonic="ja"),ENTRY,0x6f,INTERVALS)
        self.assertEqual(r["status"], "INCONCLUSIVE_MNEMONIC_BYTE_DISAGREEMENT")

    def test_wrong_branch_displacement_is_not_fourth_island(self):
        r=B.assess_signed_early_exit(disasm(branch="7e 53",target="401058"),
                                     ENTRY,0x6f,INTERVALS)
        self.assertEqual(r["status"], "INCONCLUSIVE_TARGET_NOT_FOURTH_ISLAND")

    def test_rendered_disassembly_disagrees_with_opcode(self):
        with self.assertRaises(B.SignedBranchError):
            B.assess_signed_early_exit(disasm(target="401058"),ENTRY,0x6f,INTERVALS)

    def test_wrong_entry_flags_do_not_prove_signed_rdi_predicate(self):
        r=B.assess_signed_early_exit(disasm(test="48 85 f6"),ENTRY,0x6f,INTERVALS)
        self.assertEqual(r["status"], "SIGNED_JLE_DIRECT_EDGE_TO_ISLAND_3")
        self.assertFalse(r["rdi_test_immediately_precedes"])
        self.assertEqual(r["source_register_if_tested"], "UNKNOWN")

    def test_movable_register_setup_before_test_and_signed_branch(self):
        text = ("0000000000401000 <fixture_target>:\n"
                "  401000: 48 89 f9    mov %rdi,%rcx\n"
                "  401003: 48 85 ff    test %rdi,%rdi\n"
                "  401006: 7e 60       jle 401068 <fixture_target+0x68>\n")
        r=B.assess_signed_early_exit(text, ENTRY, 0x6f, INTERVALS)
        self.assertEqual(r["status"], "SIGNED_JLE_DIRECT_EDGE_TO_ISLAND_3")
        self.assertEqual(r["branch_pc_rva"], 6)
        self.assertTrue(r["rdi_test_immediately_precedes"])

    def test_wrong_interval_count_does_not_promote(self):
        r=B.assess_signed_early_exit(disasm(), ENTRY, 0x6f, INTERVALS[:1])
        self.assertEqual(r["status"], "INCONCLUSIVE_NOT_FOUR_CODE_INTERVALS")

    def test_reject_unbounded_and_invalid_data(self):
        for args in (("",0,0,INTERVALS),("x"*300000,ENTRY,0x6f,INTERVALS),
                     (disasm(),ENTRY,70000,INTERVALS),
                     (disasm(),ENTRY,0x6f,[(ENTRY-1,ENTRY),(ENTRY+0x20,ENTRY+0x52),
                                       (ENTRY+0x58,ENTRY+0x61),(ENTRY+0x68,ENTRY+0x6f)])):
            with self.subTest(args=str(args)[:65]):
                with self.assertRaises(B.SignedBranchError):
                    B.assess_signed_early_exit(*args)

    def test_absent_or_duplicate_heading_rejected(self):
        for bad in (disasm().replace("<fixture_target>:", "<other>:"),
                    disasm()+disasm()):
            with self.assertRaises(B.SignedBranchError):
                B.assess_signed_early_exit(bad, ENTRY, 0x6f, INTERVALS)

if __name__ == "__main__":
    unittest.main()
