import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1i_selector_destination.py"
SPEC = importlib.util.spec_from_file_location("d1i", SCRIPT)
d1i = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1i)


class D1iTests(unittest.TestCase):
    def test_normalize_selector_conditions(self):
        self.assertEqual(d1i.normalize_condition("linux_fs_start"), {0: False, 1: True})
        self.assertEqual(d1i.normalize_condition("!linux_fs_start"), {0: True, 1: False})
        self.assertEqual(d1i.normalize_condition("(linux_fs_start == 0)"), {0: True, 1: False})
        self.assertEqual(d1i.normalize_condition("1 != linux_fs_start"), {0: True, 1: False})

    def test_ternary_mapping(self):
        self.assertEqual(
            d1i.ternary_mapping('linux_fs_start ? "filesystem2" : "filesystem"'),
            {"0": "filesystem", "1": "filesystem2"},
        )

    def test_post_switch_reduction_is_bounded_and_lhs_specific(self):
        text = r'''
void f(void) {
  new_name = linux_fs_start ? "before1" : "before0";
  switch (linux_fs_start) {
    case 0: linux_fs_start = 0; break;
    case 1: break;
    default: linux_fs_start = 0; break;
  }
  other = linux_fs_start ? "wrong1" : "wrong0";
  new_name = linux_fs_start ? "filesystem2" : "filesystem";
}
void g(void) {
  new_name = linux_fs_start ? "after1" : "after0";
}
'''
        r = d1i.reduce_post_switch_mapping(text)
        self.assertTrue(r["switchFound"])
        self.assertTrue(r["switchClosed"])
        self.assertEqual(r["candidateAssignmentCount"], 1)
        self.assertEqual(
            r["normalizedMappings"][0]["caseMapping"],
            {"0": "filesystem", "1": "filesystem2"},
        )

    def test_crosscheck(self):
        selected = {
            "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c": 'new_name = "filesystem";',
            "sources/kernel/linux/drivers/mtd/avm/partparse.c": 'name = "filesystem";',
            "sources/kernel/linux/arch/mips/boot/dts/lantiq/avm/grx_common.dtsi": 'label = "filesystem2";',
        }
        checks = d1i.crosscheck(["filesystem", "filesystem2"], selected)
        self.assertTrue(all(x["independentlyObserved"] for x in checks))

    def test_classification_requires_independent_crosscheck_for_strong_form(self):
        reduction = {
            "switchFound": True,
            "switchClosed": True,
            "candidateAssignmentCount": 1,
            "normalizedMappings": [{"caseMapping": {"0": "a", "1": "b"}}],
        }
        self.assertEqual(
            d1i.classify(reduction, [{"destination": "a", "independentlyObserved": True}], []),
            "H0_D1I_SELECTOR_DESTINATION_MAPPING_CROSSCHECKED",
        )
        self.assertEqual(
            d1i.classify(reduction, [{"destination": "a", "independentlyObserved": False}], []),
            "H0_D1I_SELECTOR_DESTINATION_MAPPING_CROSSCHECK_PARTIAL",
        )


if __name__ == "__main__":
    unittest.main()
