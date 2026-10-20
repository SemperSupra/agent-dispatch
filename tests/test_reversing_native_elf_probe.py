"""Adversarial native GDB parser tests on a fixed public synthetic fixture."""
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "scripts" / "reversing_native_elf_probe.py"
S = importlib.util.spec_from_file_location("native_reversing_receipt_test", P)
N = importlib.util.module_from_spec(S)
S.loader.exec_module(N)

PC = "RE_PC=0x401122"
EXIT = "[Inferior 1 (process 12345) exited normally]"

class GdbExitReceiptTests(unittest.TestCase):
    def parse(self, *lines):
        return N.parse_gdb_pc("\n".join(lines) + "\n")

    def test_native_gdb_ordered_normal_exit(self):
        self.assertEqual(self.parse("Breakpoint 1, fixture_target ()", PC, EXIT), 0x401122)

    def test_stdout_substring_not_inferior_exit(self):
        with self.assertRaises(N.OracleError):
            self.parse(PC, "application says: exited normally")

    def test_signal_rejected_even_with_clean_exit_line(self):
        with self.assertRaises(N.OracleError):
            self.parse(PC, "Program received signal SIGSEGV, Segmentation fault.", EXIT)

    def test_breakpoint_insertion_failure_rejected(self):
        with self.assertRaises(N.OracleError):
            self.parse("Cannot insert breakpoint 1.", PC, EXIT)

    def test_no_pc_rejected(self):
        with self.assertRaises(N.OracleError):
            self.parse(EXIT)

    def test_duplicate_pc_rejected(self):
        with self.assertRaises(N.OracleError):
            self.parse(PC, PC, EXIT)

    def test_duplicate_exit_rejected(self):
        with self.assertRaises(N.OracleError):
            self.parse(PC, EXIT, "[Inferior 2 (process 12346) exited normally]")

    def test_exit_before_pc_not_completion(self):
        with self.assertRaises(N.OracleError):
            self.parse(EXIT, PC)

    def test_abnormal_exit_rejected(self):
        with self.assertRaises(N.OracleError):
            self.parse(PC, "[Inferior 1 (process 12345) exited with code 01]")

if __name__ == "__main__":
    unittest.main()
