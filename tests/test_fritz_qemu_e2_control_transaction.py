import importlib.util,pathlib,unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_control_transaction.py"
SPEC=importlib.util.spec_from_file_location("r8",SCRIPT);r8=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r8)

class R8Tests(unittest.TestCase):
 def test_exchange_present(self):
  c={"controlIoTrace":{"calls":{"connect":1},"bytes":{"write":10,"read":5,"send":0,"recv":0}}}
  self.assertTrue(r8.exchange_present(c))
 def test_classify_no_transition(self):
  rt={"start":{"exitCode":0,"controlIoTrace":{"calls":{"connect":1},"bytes":{"write":1,"read":1}}},
      "statusChanged":False,"ctlmgrProcessObserved":False}
  self.assertEqual(r8.classify(rt),"E2_R8_CONTROL_EXCHANGE_NO_STATE_TRANSITION")
 def test_trace_parser(self):
  raw='1 socket(PF_LOCAL,SOCK_STREAM,0) = 3\n1 connect(3,0x1,110) = 0\n1 write(3,0x2,8) = 8\n1 read(3,0x3,4) = 4\n'
  t=r8.r6.control_io_trace(raw)
  self.assertEqual(t["socketFdCount"],1)
  self.assertEqual(t["bytes"]["write"],8)
  self.assertEqual(t["bytes"]["read"],4)

if __name__=="__main__":unittest.main()
