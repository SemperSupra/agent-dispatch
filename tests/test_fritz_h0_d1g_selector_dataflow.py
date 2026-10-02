import importlib.util
import pathlib
import unittest

SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_h0_d1g_selector_dataflow.py"
SPEC=importlib.util.spec_from_file_location("d1g",SCRIPT)
d1g=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d1g)

class D1gTests(unittest.TestCase):
    def test_direct_getter_and_numeric_parse(self):
        text='''
void f(void) {
  char *p = prom_getenv("linux_fs_start");
  unsigned long selector = 0;
  int res = kstrtoul(p, 0, &selector);
  if (selector == 0) { new_name = "rootfs"; }
}
'''
        d=d1g.reduce({"x.c":text})
        self.assertEqual(d["derived"]["getterAssignmentCount"],1)
        self.assertEqual(d["getterAssignments"][0]["assignedVariable"],"p")
        self.assertEqual(d["numericParseRelations"][0]["inputVariable"],"p")
        self.assertIn("selector",d["selectorVariables"])
        self.assertGreaterEqual(d["derived"]["selectorConditionCount"],1)
        self.assertEqual(d["selectorBranchAssignments"][0]["assignments"][0]["rhsKind"],"string-hash")
        self.assertNotIn("rootfs",str(d["selectorBranchAssignments"]))

    def test_setter_relation_is_bounded(self):
        text='prom_setenv("linux_fs_start", value);'
        d=d1g.reduce({"x.c":text})
        self.assertEqual(d["derived"]["directSetterKeyCallCount"],1)

if __name__=="__main__":
    unittest.main()
