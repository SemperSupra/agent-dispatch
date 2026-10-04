import importlib.util, pathlib, unittest
P=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_d18d_downstream_role.py"
S=importlib.util.spec_from_file_location("m",P); m=importlib.util.module_from_spec(S); S.loader.exec_module(m)
class T(unittest.TestCase):
    def test_earned_role(self):
        r={"oracleSatisfied":True,"target":{"expectedBytes":1},"library":{"combinedAcceptedCallEdges":[
            {"source":"_svctl_init","target":"_svctl_send"},
            {"source":"_svctl_send_pkt","target":"_svctl_send"},
            {"source":"_svctl_send","target":"send"}]}}
        o=m.reconcile(r)
        self.assertEqual(o["classification"],"E2_D18D_DOWNSTREAM_SEND_ROLE_EARNED")
        self.assertFalse(o["reconciliation"]["d18FunctionEntryClaimAccepted"])
        self.assertTrue(o["reconciliation"]["downstreamObservationPointMechanicallyEarned"])
    def test_missing_edge_fails_closed(self):
        r={"oracleSatisfied":True,"target":{},"library":{"combinedAcceptedCallEdges":[]}}
        o=m.reconcile(r)
        self.assertFalse(o["oracleSatisfied"])
if __name__=="__main__": unittest.main()
