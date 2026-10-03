import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1l_selector_arm_skeleton.py"
SPEC = importlib.util.spec_from_file_location("d1l", SCRIPT)
d1l = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1l)


class D1lTests(unittest.TestCase):
    def test_expression_skeleton_roles(self):
        s = d1l.expression_skeleton("lookup(parts[ROOTFS].name)")
        self.assertEqual(s["identifiers"], ["ROOTFS", "lookup", "name", "parts"])
        self.assertIn("function_like_call", s["identifierRoles"]["lookup"])
        self.assertIn("array_base", s["identifierRoles"]["parts"])
        self.assertIn("member_name", s["identifierRoles"]["name"])
        self.assertIn("macro_like", s["identifierRoles"]["ROOTFS"])
        self.assertIn("index", s["operatorClasses"])

    def test_recover_selector_arm_skeletons(self):
        text = r'''
void f(void) {
  new_name = (linux_fs_start == 0)
      ? lookup(parts[ROOTFS].name)
      : lookup(parts[ROOTFS2].name);
}
'''
        r = d1l.recover_arm_skeletons(text)
        self.assertEqual(r["selectorBearingAssignmentCount"], 1)
        e = r["decoded"][0]
        self.assertTrue(e["conditionNormalized"])
        self.assertEqual(e["conditionTruthBySelector"], {"0": True, "1": False})
        self.assertIn("ROOTFS", e["trueArmSkeleton"]["identifiers"])
        self.assertIn("ROOTFS2", e["falseArmSkeleton"]["identifiers"])

    def test_identifier_crosscheck(self):
        selected = {
            "sources/kernel/linux/drivers/mtd/avm/avm_mtd.c": "ROOTFS",
            "sources/kernel/linux/drivers/mtd/avm/partparse.c": "ROOTFS ROOTFS2",
        }
        out = d1l.identifier_crosscheck(["ROOTFS", "ROOTFS2"], selected)
        self.assertTrue(all(x["independentlyObservedOutsideAvmMtd"] for x in out))


if __name__ == "__main__":
    unittest.main()
