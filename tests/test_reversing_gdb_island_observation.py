"""Independent red-team tests of typed native GDB island observations."""
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "scripts/reversing_gdb_island_observation.py"
S = importlib.util.spec_from_file_location("islands", P)
M = importlib.util.module_from_spec(S)
S.loader.exec_module(M)
ADDR = 0x401000


def sample(status, address=ADDR):
    header = f"Breakpoint 1 at 0x{ADDR:x}\n"
    if status == "hit":
        return header + f"Breakpoint 1, 0x{address:x} in ?? ()\n"
    if status == "exit":
        return header + "[Inferior 1 (process 114) exited normally]\n"
    return header


class TypedGdbIslandTests(unittest.TestCase):
    def test_exact_hit(self):
        self.assertEqual(M.classify_gdb_single_breakpoint(sample("hit"), ADDR),
                         "BREAKPOINT_OBSERVED")

    def test_not_observed_not_unreachable(self):
        self.assertEqual(M.classify_gdb_single_breakpoint(sample("exit"), ADDR),
                         "NOT_OBSERVED_IN_THIS_RUN")

    def test_wrong_breakpoint_pc_denied(self):
        with self.assertRaises(M.IslandObservationError):
            M.classify_gdb_single_breakpoint(sample("hit", ADDR + 1), ADDR)

    def test_missing_installed_breakpoint_denied(self):
        with self.assertRaises(M.IslandObservationError):
            M.classify_gdb_single_breakpoint("Breakpoint 1, 0x401000 in ?? ()\n", ADDR)

    def test_unknown_and_signal_denied(self):
        for msg in (sample("none"), sample("exit") + "Program received signal SIGSEGV\n"):
            with self.subTest(msg=msg):
                with self.assertRaises(M.IslandObservationError):
                    M.classify_gdb_single_breakpoint(msg, ADDR) if "signal" not in msg else \
                        M.classify_gdb_single_breakpoint(sample("hit")+"Program received signal SIGSEGV\n", ADDR)

    def test_invalid_target_denied(self):
        for val in (-1, 2**64, True, "0x401000"):
            with self.subTest(value=str(val)):
                with self.assertRaises(M.IslandObservationError):
                    M.classify_gdb_single_breakpoint(sample("hit"), val)

    def test_bounded_source_report(self):
        def fake_run(argv, timeout=0):
            self.assertEqual(argv[0], "gdb")
            self.assertEqual(argv[2], "--nx")
            addr = int(argv[argv.index("-ex") + 4].split("*0x")[1], 16) if False else \
                   int(next(s.split("*0x")[1] for s in argv if s.startswith("break *0x")), 16)
            head = f"Breakpoint 1 at 0x{addr:x}\n"
            return head + (f"Breakpoint 1, 0x{addr:x} in ?? ()\n" if addr == ADDR
                           else "[Inferior 1 (process 123) exited normally]\n")
        r = M.probe_static_intervals("/tmp/synthetic-stripped-only",
                                     [(ADDR, ADDR + 5), (ADDR + 8, ADDR + 16)], fake_run)
        self.assertEqual(r["observed_count"], 1)
        self.assertEqual(r["not_observed_count"], 1)
        self.assertEqual(r["interval_count"], 2)
        self.assertIn("NOT_ALL_PATHS", r["interpretation"])

    def test_duplicate_and_malformed_intervals_denied(self):
        for spans in ([], [(ADDR, ADDR + 1), (ADDR, ADDR + 2)], [(ADDR + 1, ADDR)],
                      [(ADDR, ADDR + 1)] * 33):
            with self.subTest(spans=len(spans)):
                with self.assertRaises(M.IslandObservationError):
                    M.probe_static_intervals("ephemeral", spans, lambda *args, **kw: sample("hit"))


if __name__ == "__main__":
    unittest.main()
