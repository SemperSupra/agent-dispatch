import importlib.util,pathlib,unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_shell_function_graph.py"
SPEC=importlib.util.spec_from_file_location("d9",SCRIPT);d9=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d9)
class D9Tests(unittest.TestCase):
 def test_include(self):
  e=d9.include_edges(". /etc/init.d/rc.net\n","/x")
  self.assertEqual(e[0]["includedPath"],"/etc/init.d/rc.net")
 def test_function_relation(self):
  text="start_service() {\n /bin/svctl start $1\n}\n"
  s=d9.function_semantics(text,"/lib")
  self.assertEqual(s[0]["function"],"start_service")
  self.assertEqual(s[0]["svctl"][0]["verb"],"start")
 def test_cross_file_resolution(self):
  lib="start_service() {\n /bin/svctl start $1\n}\n"
  caller=". /etc/init.d/rc.net\nstart_service ctlmgr\n"
  fs=d9.function_semantics(lib,"/etc/init.d/rc.net")
  calls=d9.function_calls(caller,"/etc/init.d/rc.ptest.env",{"start_service"})
  sem={"start_service":fs}
  rel=d9.resolve_call_to_svctl(calls[0],sem,[])
  self.assertEqual(rel[0]["operand"],"ctlmgr")
  self.assertEqual(rel[0]["verb"],"start")
if __name__=="__main__":unittest.main()
