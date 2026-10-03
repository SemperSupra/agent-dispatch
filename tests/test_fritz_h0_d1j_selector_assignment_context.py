import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1j_selector_assignment_context.py"
SPEC = importlib.util.spec_from_file_location("d1j", SCRIPT)
d1j = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1j)


class D1jTests(unittest.TestCase):
    def test_statement_end_handles_ternary_and_strings(self):
        text = 'new_name = selector ? "a;b" : "b"; next();'
        self.assertEqual(text[d1j.statement_end(text, 0)], ";")

    def test_assignment_inventory_removes_same_block_assumption(self):
        text = r'''
const char *new_name;
void f(void) {
  if (linux_fs_start) {
    new_name = "filesystem2";
  }
  switch (linux_fs_start) {
    case 0: break;
    case 1: break;
    default: linux_fs_start = 0; break;
  }
}
void g(void) {
  new_name = linux_fs_start ? "filesystem2" : "filesystem";
}
'''
        inv = d1j.assignment_contexts(text)
        self.assertTrue(inv["switchFound"])
        self.assertTrue(inv["switchClosed"])
        self.assertEqual(inv["assignmentCount"], 2)
        self.assertEqual(inv["selectorBearingAssignmentCount"], 1)
        after = [x for x in inv["contexts"] if x.get("selectorReferenceCount") == 1][0]
        self.assertEqual(after["relativeToSelectorSwitch"], "after_switch")
        self.assertFalse(after["sameEnclosingBlockAsSelectorSwitch"])
        self.assertTrue(after["simpleSelectorTernaryRecognized"])
        self.assertEqual(after["safeDestinationTokens"], ["filesystem", "filesystem2"])

    def test_comments_do_not_create_assignments(self):
        text = r'''
void f(void) {
  // new_name = linux_fs_start ? "fake1" : "fake0";
  switch (linux_fs_start) { case 0: break; }
  const char *s = "new_name = fake";
}
'''
        inv = d1j.assignment_contexts(text)
        self.assertEqual(inv["assignmentCount"], 0)

    def test_crosscheck(self):
        selected = {
            "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c": 'new_name = "filesystem";',
            "sources/kernel/linux/drivers/mtd/avm/partparse.c": 'name = "filesystem";',
            "sources/kernel/linux/arch/mips/boot/dts/lantiq/avm/grx_common.dtsi": 'label = "filesystem2";',
        }
        checks = d1j.crosscheck(["filesystem", "filesystem2"], selected)
        self.assertTrue(all(x["independentlyObserved"] for x in checks))

    def test_classify(self):
        self.assertEqual(
            d1j.classify(
                {"selectorBearingAssignmentCount": 1, "assignmentCount": 2, "switchFound": True},
                [],
            ),
            "H0_D1J_SELECTOR_BOUND_ASSIGNMENT_CONTEXT_RECOVERED",
        )
        self.assertEqual(
            d1j.classify(
                {"selectorBearingAssignmentCount": 0, "assignmentCount": 2, "switchFound": True},
                [],
            ),
            "H0_D1J_NEW_NAME_ASSIGNMENT_CONTEXT_RECOVERED",
        )


if __name__ == "__main__":
    unittest.main()
