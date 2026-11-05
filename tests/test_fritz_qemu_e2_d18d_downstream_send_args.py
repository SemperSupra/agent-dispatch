import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d18d_downstream_send_args.py"
SPEC = importlib.util.spec_from_file_location("d18d", SCRIPT)
d18d = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d18d)


class D18dTests(unittest.TestCase):
    def test_classify_write_tags_only_accepted_sizes(self):
        self.assertEqual(
            d18d.classify_arg_write("li a2,8", "a2")["acceptedSizeClass"],
            "accepted_r9_size_8",
        )
        self.assertEqual(
            d18d.classify_arg_write("li a2,260", "a2")["acceptedSizeClass"],
            "accepted_r9_size_260",
        )
        self.assertNotIn(
            "acceptedSizeClass",
            d18d.classify_arg_write("li a2,17", "a2"),
        )

    def test_selected_jalr_rejects_clobber_and_branch(self):
        self.assertEqual(
            d18d.selected_jalr_index(
                ["lw t9,16(gp)", "move a0,s0", "jalr t9", "li a2,8"], 0
            ),
            2,
        )
        self.assertIsNone(
            d18d.selected_jalr_index(
                ["lw t9,16(gp)", "move t9,s0", "jalr t9"], 0
            )
        )
        self.assertIsNone(
            d18d.selected_jalr_index(
                ["lw t9,16(gp)", "beq a0,zero,20", "jalr t9"], 0
            )
        )

    def test_argument_signature_includes_jalr_delay_slot(self):
        ins = [
            "move a0,s0",
            "move a1,s1",
            "lw t9,16(gp)",
            "jalr t9",
            "li a2,8",
        ]
        sig = d18d.call_argument_signature(ins, 2, 3)
        self.assertEqual(sig["a0"]["setup"]["kind"], "register_move")
        self.assertEqual(sig["a1"]["setup"]["kind"], "register_move")
        self.assertEqual(
            sig["a2"]["setup"]["acceptedSizeClass"],
            "accepted_r9_size_8",
        )
        self.assertTrue(sig["a2"]["writtenInJalrDelaySlot"])

    def test_classification_accepts_exact_two_source_edges(self):
        sources = [
            {
                "source": "_svctl_init",
                "acceptedSameBlockCallsiteCount": 1,
                "acceptedSizeClasses": ["accepted_r9_size_8"],
            },
            {
                "source": "_svctl_send_pkt",
                "acceptedSameBlockCallsiteCount": 1,
                "acceptedSizeClasses": ["accepted_r9_size_260"],
            },
        ]
        self.assertEqual(
            d18d.classify(sources),
            "E2_D18D_DOWNSTREAM_SEND_ARGUMENT_ROLES_RECOVERED",
        )


if __name__ == "__main__":
    unittest.main()
