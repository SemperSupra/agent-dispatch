import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d17_svctl_callsite_args.py"
SPEC = importlib.util.spec_from_file_location("d17", SCRIPT)
d17 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d17)


class D17Tests(unittest.TestCase):
    def test_immediate_classes(self):
        self.assertEqual(d17.immediate_class("0"), "zero")
        self.assertEqual(d17.immediate_class("1"), "one")
        self.assertEqual(d17.immediate_class("7"), "small_positive")
        self.assertEqual(d17.immediate_class("-3"), "small_negative")

    def test_argument_write_classes(self):
        self.assertEqual(
            d17.classify_write("li a0,1", "a0"),
            {"kind": "immediate", "immediateClass": "one"},
        )
        self.assertEqual(
            d17.classify_write("move a1,s0", "a1"),
            {"kind": "register_move", "sourceRegisterClass": "saved"},
        )
        self.assertEqual(
            d17.classify_write("lw a2,16(sp)", "a2"),
            {"kind": "memory_load", "baseRegisterClass": "stack_frame"},
        )

    def test_selected_call_target_stops_on_clobber(self):
        self.assertTrue(
            d17.selected_call_target(
                ["lw t9,16(gp)", "move a0,s0", "jalr t9"],
                0,
            )
        )
        self.assertFalse(
            d17.selected_call_target(
                ["lw t9,16(gp)", "move t9,s0", "jalr t9"],
                0,
            )
        )

    def test_argument_signature_same_block_only(self):
        ins = [
            "li a0,1",
            "beq v0,zero,20",
            "nop",
            "move a1,s0",
            "li a2,0",
            "lw t9,16(gp)",
            "jalr t9",
        ]
        sig = d17.argument_signature(ins, 5)
        self.assertEqual(sig["a0"]["kind"], "not_set_in_block")
        self.assertEqual(sig["a1"]["kind"], "register_move")
        self.assertEqual(sig["a2"]["immediateClass"], "zero")

    def test_classification(self):
        slice_ = {
            "selectedGotLoadCount": 2,
            "targets": [
                {"target": "_svctl_init", "acceptedCallsiteCount": 1},
                {"target": "_svctl_send_pkt", "acceptedCallsiteCount": 0},
            ],
        }
        self.assertEqual(
            d17.classify(slice_, 2),
            "E2_D17_SVCTL_CALLSITE_ARGUMENT_CLASSES_RECOVERED",
        )


if __name__ == "__main__":
    unittest.main()
