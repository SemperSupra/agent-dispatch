import importlib.util,pathlib,unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_rcnet_callers.py"
SPEC=importlib.util.spec_from_file_location("d8",SCRIPT);d8=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d8)
class D8Tests(unittest.TestCase):
 def test_literal_ctlmgr(self):
  c=d8.rcnet_calls("/etc/init.d/rc.net ctlmgr\n","/x")
  self.assertEqual(c[0]["args"][0],{"kind":"service","value":"ctlmgr"})
 def test_variable_resolves(self):
  text="srv=ctlmgr\n/etc/init.d/rc.net $srv\n"
  r=d8.resolve(d8.rcnet_calls(text,"/x"),d8.simple_bindings(text,"/x"))
  self.assertEqual(r[0]["argv1"],"ctlmgr")
 def test_unbound_positional_stays_unresolved(self):
  c=d8.rcnet_calls("/etc/init.d/rc.net $1\n","/x")
  self.assertEqual(d8.resolve(c,[]),[])
if __name__=="__main__":unittest.main()
