import importlib.util,pathlib,unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_h0_d1d_selector_semantics.py"
SPEC=importlib.util.spec_from_file_location("d1d",SCRIPT);d1d=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d1d)
class D1dTests(unittest.TestCase):
 def test_prom_getenv_assignment(self):
  text='static int f(void) { char *x = prom_getenv("linux_fs_start"); if (strcmp(x,"1")==0) return 1; return 0; }'
  r=d1d.selector_calls("x.c",text)
  self.assertEqual(r[0]["keyAssignments"][0]["callee"],"prom_getenv")
  self.assertIn({"variable":"x","kind":"strcmp","value":"1"},r[0]["comparisons"])
 def test_header_name(self):
  r=d1d.reduce({"sources/kernel/linux/drivers/char/tffs/include/uapi/avm/tffs/tffs.h":"linux_fs_start"})
  self.assertTrue(r["tffsPublicNamePresent"])
if __name__=="__main__":unittest.main()
