import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d14_libsvctl_liveness.py"
SPEC = importlib.util.spec_from_file_location("d14", SCRIPT)
d14 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d14)


class D14Tests(unittest.TestCase):
    def test_accepts_live_target_beyond_old_window(self):
        ins = [
            "lw t9,-32720(gp)",
            "move a0,s0",
            "li a1,8",
            "move a2,s1",
            "move a3,s2",
            "jalr t9",
        ]
        self.assertEqual(
            d14.live_to_jalr(ins, 0),
            {"accepted": True, "reason": "same_basic_block_target_live_to_jalr"},
        )

    def test_rejects_t9_clobber(self):
        ins = [
            "lw t9,-32720(gp)",
            "move t9,s0",
            "jalr t9",
        ]
        self.assertEqual(
            d14.live_to_jalr(ins, 0),
            {"accepted": False, "reason": "t9_clobbered_before_jalr"},
        )

    def test_rejects_basic_block_exit(self):
        ins = [
            "lw t9,-32720(gp)",
            "beq a0,zero,20",
            "nop",
            "jalr t9",
        ]
        self.assertEqual(
            d14.live_to_jalr(ins, 0),
            {"accepted": False, "reason": "basic_block_ended_before_jalr"},
        )

    def test_write_and_transfer_detection(self):
        self.assertTrue(d14.writes_t9("lw t9,0(sp)"))
        self.assertFalse(d14.writes_t9("sw t9,0(sp)"))
        self.assertTrue(d14.control_transfer("bne a0,zero,20"))
        self.assertTrue(d14.control_transfer("jalr t9"))
        self.assertFalse(d14.control_transfer("addiu sp,sp,-32"))

    def test_classify(self):
        funcs = [{"acceptedLivePicCallCount": 1, "selectedGotLoadCount": 1}]
        self.assertEqual(
            d14.classify(funcs, 2),
            "E2_D14_LIBSVCTL_LIVENESS_EDGES_RECOVERED",
        )


if __name__ == "__main__":
    unittest.main()
