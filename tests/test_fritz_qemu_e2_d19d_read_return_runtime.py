import importlib.util,pathlib,unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_d19d_read_return_runtime.py"
SPEC=importlib.util.spec_from_file_location("d19d",SCRIPT); d19d=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(d19d)
class T(unittest.TestCase):
  def test_parse_return(self):
    self.assertEqual(d19d.parse_return('FRITZRET:{"scalarClass":"zero"}\n'),[{"scalarClass":"zero"}])
  def test_classify(self):
    base={"allCallsInstrumentationReady":True,"allExpectedReturnHits":True,"prePostStatusStable":True,"startDiffersFromStableStatus":False}
    self.assertEqual(d19d.classify(base),"E2_D19D_SVCTL_READ_RETURN_CLASS_NO_DISCRIMINATOR")
    self.assertEqual(d19d.classify(dict(base,startDiffersFromStableStatus=True)),"E2_D19D_SVCTL_READ_RETURN_CLASS_DISCRIMINATOR_FOUND")
    self.assertEqual(d19d.classify(dict(base,prePostStatusStable=False)),"E2_D19D_SVCTL_READ_RETURN_STATUS_UNSTABLE")
if __name__=="__main__": unittest.main()
