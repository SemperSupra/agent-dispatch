import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d15_libsvctl_successor_liveness.py"
SPEC = importlib.util.spec_from_file_location("d15", SCRIPT)
d15 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d15)


def rec(addr, asm):
    return {"addr": addr, "asm": asm}


class D15Tests(unittest.TestCase):
    def test_instruction_records_and_target(self):
        text = """
  1000: 8f990010  lw t9,16(gp)
  1004: 10800002  beq a0,zero,1010 <x>
  1008: 00000000  nop
  100c: 0320f809  jalr t9
"""
        records = d15.instruction_records(text)
        self.assertEqual(len(records), 4)
        self.assertEqual(d15.branch_target_addr(records[1]["asm"]), 0x1010)

    def test_conditional_fallthrough_accepts_live_target(self):
        records = [
            rec(0x1000, "lw t9,16(gp)"),
            rec(0x1004, "beq a0,zero,1014 <x>"),
            rec(0x1008, "nop"),
            rec(0x100c, "move a0,s0"),
            rec(0x1010, "jalr t9"),
            rec(0x1014, "move v0,zero"),
        ]
        result = d15.successor_liveness(records, 0)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["boundaryClass"], "conditional")
        self.assertEqual(result["successorOutcomes"]["fallthrough"], "successor_target_live_to_jalr")

    def test_normal_branch_delay_slot_clobber_blocks_paths(self):
        records = [
            rec(0x1000, "lw t9,16(gp)"),
            rec(0x1004, "beq a0,zero,1014 <x>"),
            rec(0x1008, "move t9,s0"),
            rec(0x100c, "jalr t9"),
            rec(0x1010, "nop"),
            rec(0x1014, "jalr t9"),
        ]
        result = d15.successor_liveness(records, 0)
        self.assertFalse(result["accepted"])
        self.assertEqual(set(result["successorOutcomes"].values()), {"delay_slot_t9_clobbered"})

    def test_branch_likely_annuls_delay_slot_on_fallthrough(self):
        records = [
            rec(0x1000, "lw t9,16(gp)"),
            rec(0x1004, "beql a0,zero,1014 <x>"),
            rec(0x1008, "move t9,s0"),
            rec(0x100c, "jalr t9"),
            rec(0x1010, "nop"),
            rec(0x1014, "move v0,zero"),
        ]
        result = d15.successor_liveness(records, 0)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["successorOutcomes"]["taken"], "delay_slot_t9_clobbered")
        self.assertEqual(result["successorOutcomes"]["fallthrough"], "successor_target_live_to_jalr")

    def test_second_control_transfer_stops_path(self):
        records = [
            rec(0x1000, "lw t9,16(gp)"),
            rec(0x1004, "b 1010 <x>"),
            rec(0x1008, "nop"),
            rec(0x100c, "nop"),
            rec(0x1010, "beq a0,zero,1020 <y>"),
            rec(0x1014, "nop"),
            rec(0x1018, "jalr t9"),
        ]
        result = d15.successor_liveness(records, 0)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["successorOutcomes"]["taken"], "second_control_transfer_before_jalr")

    def test_classification(self):
        recovered = {"acceptedReadCallEdgeCount": 1, "selectedReadGotLoadCount": 1}
        partial = {"acceptedReadCallEdgeCount": 0, "selectedReadGotLoadCount": 1}
        self.assertEqual(d15.classify(recovered, 2), "E2_D15_LIBSVCTL_READ_EDGE_RECOVERED")
        self.assertEqual(d15.classify(partial, 2), "E2_D15_LIBSVCTL_SUCCESSOR_PARTIAL")


if __name__ == "__main__":
    unittest.main()
