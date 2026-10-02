import importlib.util
import pathlib
import unittest

SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_h0_d1h_selector_switch.py"
SPEC=importlib.util.spec_from_file_location("d1h",SCRIPT)
d1h=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d1h)

class D1hTests(unittest.TestCase):
    def test_switch_cases_and_safe_destinations(self):
        text='''
void f(void) {
 switch (linux_fs_start) {
  case 0:
   new_name = "filesystem";
   break;
  case 1:
   new_name = "filesystem2";
   break;
  default:
   recover = 1;
   break;
 }
}
'''
        sw=d1h.reduce_switch(text)
        self.assertTrue(sw["switchFound"])
        self.assertEqual(len(sw["cases"]),3)
        self.assertEqual(sw["cases"][0]["caseValue"],0)
        self.assertEqual(sw["cases"][0]["safeDestinations"],["filesystem"])
        self.assertEqual(sw["cases"][1]["caseValue"],1)
        self.assertEqual(sw["cases"][1]["safeDestinations"],["filesystem2"])
        self.assertEqual(sw["cases"][2]["caseKind"],"default")

    def test_unsafe_string_is_hashed(self):
        rec=d1h.safe_assignment("other",'"/a path with spaces"')
        self.assertEqual(rec["rhsKind"],"string-hash")
        self.assertNotIn("a path",str(rec))

if __name__=="__main__":
    unittest.main()
