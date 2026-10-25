"""Adversarial typed GDB entry-argument intervention tests; no target needed."""
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "scripts/reversing_gdb_rdi_intervention.py"
S = importlib.util.spec_from_file_location("rdi_intervene", P)
M = importlib.util.module_from_spec(S)
S.loader.exec_module(M)
ENTRY = 0x401000
ISLAND = ENTRY + 16


def evidence(n, hit=True, target=ISLAND, after=None, before=7, entry_pc=ENTRY,
             corrupt_target=False, fake_exit=False, signal=False):
    text = (f"Breakpoint 1 at 0x{ENTRY:x}\n"
            + (f"Breakpoint 2 at 0x{target:x}\n" if target != ENTRY else "")
            + f"Breakpoint 1, 0x{ENTRY:x} in ?? ()\n"
            + f"RE_RDI_ENTRY_PC=0x{entry_pc:x}\n"
            + f"RE_RDI_BEFORE={before}\n"
            + f"RE_RDI_AFTER={n if after is None else after}\n")
    if hit and target != ENTRY:
        text += f"Breakpoint 2, 0x{target+(1 if corrupt_target else 0):x} in ?? ()\n"
    if (not hit or fake_exit) and target != ENTRY:
        text += "[Inferior 1 (process 321) exited normally]\n"
    if signal:
        text += "Program received signal SIGSEGV\n"
    return text


class InterventionTests(unittest.TestCase):
    def test_verified_island_hit(self):
        self.assertEqual(M.parse_intervention_receipt(evidence(8), ENTRY, ISLAND, 8),
                         "BREAKPOINT_OBSERVED_AFTER_RDI_INTERVENTION")

    def test_verified_clean_nonhit_is_unknown(self):
        self.assertEqual(M.parse_intervention_receipt(evidence(4, hit=False), ENTRY, ISLAND, 4),
                         "NOT_OBSERVED_IN_THIS_INTERVENED_RUN")

    def test_entry_control_alone(self):
        self.assertEqual(M.parse_intervention_receipt(evidence(12, target=ENTRY), ENTRY, ENTRY, 12),
                         "ENTRY_PC_OBSERVED_AND_RDI_ATTESTED")

    def test_wrong_entry_pc_is_rejected(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(8, entry_pc=ENTRY+1), ENTRY, ISLAND, 8)

    def test_wrong_rdi_pre_and_post_rejected(self):
        for kwargs in ({"before": 9}, {"after": 9}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(M.InterventionError):
                    M.parse_intervention_receipt(evidence(8, **kwargs), ENTRY, ISLAND, 8)

    def test_wrong_target_hit_rejected(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(8, corrupt_target=True), ENTRY, ISLAND, 8)

    def test_signal_even_with_clean_exit_rejected(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(8, hit=False, signal=True), ENTRY, ISLAND, 8)

    def test_missing_entry_breakpoint_rejected(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(8).replace(f"Breakpoint 1, 0x{ENTRY:x} in ?? ()\n", ""),
                                         ENTRY, ISLAND, 8)

    def test_reject_untrusted_arguments(self):
        for n in (7, 100, -2, True, "8", None):
            with self.subTest(n=n):
                with self.assertRaises(M.InterventionError):
                    M.parse_intervention_receipt(evidence(8), ENTRY, ISLAND, n)

    def test_signed_zero_and_negative_register_witnesses(self):
        for n in (0, -1):
            with self.subTest(n=n):
                result = M.parse_intervention_receipt(evidence(n), ENTRY, ISLAND, n)
                self.assertEqual(result, "BREAKPOINT_OBSERVED_AFTER_RDI_INTERVENTION")

    def test_negative_wrong_register_value_rejected(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(-1, after=(2**64)-1),
                                         ENTRY, ISLAND, -1)

    def test_no_forged_exit_message(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(8, hit=False).replace(
                "[Inferior 1 (process 321) exited normally]", "ordinary stdout exited normally"),
                ENTRY, ISLAND, 8)

    def test_reject_hit_before_attested_rdi_write(self):
        original = evidence(8)
        hit = f"Breakpoint 2, 0x{ISLAND:x} in ?? ()\n"
        self.assertEqual(original.count(hit), 1)
        reordered = original.replace(hit, "").replace("RE_RDI_ENTRY_PC=",
                                                        hit+"RE_RDI_ENTRY_PC=", 1)
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(reordered, ENTRY, ISLAND, 8)

    def test_reject_exit_before_attested_rdi_write(self):
        original = evidence(4, hit=False)
        exitline = "[Inferior 1 (process 321) exited normally]\n"
        self.assertEqual(original.count(exitline), 1)
        reordered = original.replace(exitline, "").replace("RE_RDI_BEFORE=",
                                                             exitline+"RE_RDI_BEFORE=", 1)
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(reordered, ENTRY, ISLAND, 4)

    def test_refuse_simultaneous_target_hit_and_normal_exit(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(8, fake_exit=True), ENTRY, ISLAND, 8)

    def test_refuse_duplicate_normal_exit(self):
        receipt = evidence(4, hit=False)
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(receipt +
                "[Inferior 2 (process 322) exited normally]\n", ENTRY, ISLAND, 4)

    def test_refuse_abnormal_exit_even_with_target_hit(self):
        with self.assertRaises(M.InterventionError):
            M.parse_intervention_receipt(evidence(8) +
                "[Inferior 1 (process 321) exited with code 01]\n", ENTRY, ISLAND, 8)

    def test_bounded_fixed_argv_and_fresh_process(self):
        seen = []
        def runner(argv, timeout=0):
            self.assertEqual(argv[:4], ["gdb", "--batch", "--nx", "--quiet"])
            self.assertEqual(timeout, 35)
            self.assertIn("set pagination off", argv)
            injected = next(int(x.split(" = ")[-1]) for x in argv
                            if x.startswith("set $rdi = "))
            self.assertIn(injected, M.ALLOWED_ARGUMENTS)
            self.assertIn("break *0x%x" % ENTRY, argv)
            target_cmd = [x for x in argv if x.startswith("break *0x") and
                          x != "break *0x%x" % ENTRY]
            target = int(target_cmd[0].split("*0x")[-1], 16) if target_cmd else ENTRY
            seen.append((injected,target))
            return evidence(injected, hit=target != ISLAND, target=target)
        result = M.observe_intervened_islands("/tmp/fixed-public-stripped",
                                               ENTRY, [(ENTRY,ENTRY+6),(ISLAND,ISLAND+4)], runner)
        self.assertEqual(len(seen), 2 * len(M.ALLOWED_ARGUMENTS))
        self.assertEqual(len(result["arguments"]), len(M.ALLOWED_ARGUMENTS))
        self.assertTrue(all(row["not_observed_indices"] == [1] for row in result["arguments"]))
        self.assertEqual(result["abi"], "X86_64_SYSV_FIRST_ARGUMENT_RDI")
        for sample in result["arguments"]:
            self.assertEqual(
                [x["target_delta_from_entry"] for x in sample["statuses"]],
                [0, ISLAND-ENTRY])

    def test_invalid_intervals_rejected(self):
        for spans in ([], [(ISLAND,ISLAND+1)], [(ENTRY, ENTRY)],
                      [(ENTRY,ENTRY+4),(ENTRY,ENTRY+8)],
                      [(ENTRY,ENTRY+4)] * 33):
            with self.subTest(spans=len(spans)):
                with self.assertRaises(M.InterventionError):
                    M.observe_intervened_islands("synthetic", ENTRY, spans,
                                                 lambda *_a,**_kw: "")


if __name__ == "__main__":
    unittest.main()
