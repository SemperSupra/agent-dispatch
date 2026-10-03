import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d16_libsvctl_call_return.py"
SPEC = importlib.util.spec_from_file_location("d16", SCRIPT)
d16 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d16)


def rec(addr, asm):
    return {"addr": addr, "asm": asm}


class D16Tests(unittest.TestCase):
    def test_transfer_and_symbol_classification(self):
        self.assertEqual(d16.transfer_class("jal 1000 <helper>"), "direct_call")
        self.assertEqual(d16.transfer_class("jalr v0"), "indirect_call")
        self.assertEqual(d16.safe_target_symbol("jal 1000 <helper>"), "helper")

    def test_post_return_fresh_reload_recovers_target(self):
        got = {16: "read"}
        records = [
            rec(0x1000, "lw t9,16(gp)"),
            rec(0x1004, "move a0,s0"),
            rec(0x1008, "jalr t9"),
        ]
        result = d16.post_return_path(records, 0, got, False)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["freshReadReloadCount"], 1)

    def test_post_return_preserved_target_reaches_jalr(self):
        result = d16.post_return_path(
            [rec(0x1000, "move a0,s0"), rec(0x1004, "jalr t9")],
            0,
            {},
            True,
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["freshReadReloadCount"], 0)

    def test_post_return_dead_target_is_not_accepted(self):
        result = d16.post_return_path(
            [rec(0x1000, "move a0,s0"), rec(0x1004, "jalr t9")],
            0,
            {},
            False,
        )
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "post_return_jalr_without_live_read_target")

    def test_callee_preservation_predicate(self):
        # Use pure instruction predicates equivalent to the callee rule.
        safe = ["move v0,a0", "jr ra", "nop"]
        unsafe_write = ["move t9,a0", "jr ra", "nop"]
        unsafe_call = ["jalr v0", "nop", "jr ra", "nop"]
        def preserved(ins):
            return (
                sum(1 for a in ins if d16.d14.writes_t9(a)) == 0
                and sum(1 for a in ins if d16.is_call_asm(a)) == 0
                and sum(1 for a in ins if d16.is_return_asm(a)) > 0
            )
        self.assertTrue(preserved(safe))
        self.assertFalse(preserved(unsafe_write))
        self.assertFalse(preserved(unsafe_call))

    def test_classification(self):
        accepted = {"acceptedReadCallEdge": True, "selectedReadGotLoadCount": 1, "firstTransferClass": "direct_call"}
        partial = {"acceptedReadCallEdge": False, "selectedReadGotLoadCount": 1, "firstTransferClass": "direct_call"}
        self.assertEqual(d16.classify(accepted, 2), "E2_D16_LIBSVCTL_READ_EDGE_RECOVERED")
        self.assertEqual(d16.classify(partial, 2), "E2_D16_LIBSVCTL_CALL_RETURN_PARTIAL")


if __name__ == "__main__":
    unittest.main()
