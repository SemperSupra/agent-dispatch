import json,pathlib,unittest
DOC=pathlib.Path(__file__).parents[1]/"evidence"/"fritz-e2-d19g-response-closure.json"
class T(unittest.TestCase):
  def setUp(self): self.r=json.loads(DOC.read_text(encoding="utf-8"))
  def test_closure(self):
    self.assertEqual(self.r["classification"],"E2_D19G_CALLER_RETURN_RESPONSE_BRANCH_EXHAUSTED")
    self.assertTrue(self.r["oracleSatisfied"])
    c=self.r["convergence"]
    self.assertFalse(c["entryDimensionsDiscriminateStart"])
    self.assertFalse(c["returnScalarClassDiscriminatesStart"])
    self.assertFalse(c["callerBranchRelationDiscriminatesStart"])
    self.assertTrue(c["statusControlsStableAcrossAllRuntimeReps"])
    x=self.r["closure"]
    self.assertTrue(x["callerReturnBranchClosed"])
    self.assertTrue(x["newResponseExperimentRequiresNewMechanicallyEarnedEvidence"])
  def test_boundaries(self):
    b=self.r["interpretationBoundary"]
    self.assertTrue(b["r9ResponseClassDifferenceStillAccepted"])
    self.assertFalse(b["responseDifferenceExplained"])
    for k in ("libcReadOwnershipInferred","responseFieldLayoutAccepted","protocolEnumValuesAccepted",
              "payloadOffsetsAccepted","physicalRouterContact","modifiedHilAuthorized"):
      self.assertFalse(b[k],k)
if __name__=="__main__": unittest.main()
