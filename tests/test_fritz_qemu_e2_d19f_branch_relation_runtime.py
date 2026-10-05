import importlib.util,pathlib,unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_d19f_branch_relation_runtime.py"
SPEC=importlib.util.spec_from_file_location("d19f",SCRIPT);d19f=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d19f)
class T(unittest.TestCase):
  def test_parse(self):
    self.assertEqual(d19f.parse_obs('FRITZREL:{"equal":true,"peerClass":"saved","v0Class":"one"}\n'),
      [{"equal":True,"peerClass":"saved","v0Class":"one"}])
  def test_classify(self):
    b={"allCallsInstrumentationReady":True,"allExpectedHits":True,"prePostStatusStable":True,"startDiffersFromStableStatus":False}
    self.assertEqual(d19f.classify(b),"E2_D19F_BRANCH_RELATION_NO_DISCRIMINATOR")
    self.assertEqual(d19f.classify(dict(b,startDiffersFromStableStatus=True)),"E2_D19F_BRANCH_RELATION_DISCRIMINATOR_FOUND")
if __name__=="__main__":unittest.main()
