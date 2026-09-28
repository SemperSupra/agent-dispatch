import importlib.util, pathlib, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("g",ROOT/"scripts"/"github_runner_guest_receipt.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class T(unittest.TestCase):
  def test_parse(self):
    with tempfile.TemporaryDirectory() as td:
      p=pathlib.Path(td)/"x"; p.write_text("A=1\nB=two\n"); self.assertEqual(MOD.parse(p),{"A":"1","B":"two"})
  def test_intval(self):
    self.assertEqual(MOD.intval("4"),4); self.assertIsNone(MOD.intval(""))
if __name__=="__main__": unittest.main()
