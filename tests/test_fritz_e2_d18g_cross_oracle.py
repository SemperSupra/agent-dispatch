import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "evidence" / "fritz-e2-d18g-cross-oracle.json"

class FritzD18gCrossOracleTest(unittest.TestCase):
    def setUp(self):
        self.r = json.loads(DOC.read_text(encoding="utf-8"))

    def test_exact_classification_and_oracle(self):
        self.assertEqual(self.r["schemaVersion"], "fritz-e2-d18g-cross-oracle/v1")
        self.assertEqual(self.r["classification"], "E2_D18G_REQUEST_DISCRIMINATOR_CROSS_ORACLE_CONVERGED")
        self.assertIs(self.r["oracleSatisfied"], True)

    def test_wire_and_runtime_relations_converge(self):
        a = self.r["acceptedRelations"]
        r9 = a["r9"]
        self.assertIs(r9["statusRequestsEquivalent"], True)
        self.assertIs(r9["startRequestDiffers"], True)
        self.assertEqual(r9["firstObservedSendChunkBytes"], 8)
        self.assertIs(r9["firstObservedSendChunkDiffersForStart"], True)
        self.assertEqual(r9["secondObservedSendChunkBytes"], 260)
        self.assertIs(r9["secondObservedSendChunkInvariant"], True)

        topo = a["staticTopology"]
        self.assertIs(topo["initContainsFixed8"], True)
        self.assertIs(topo["initToSend"], True)
        self.assertIs(topo["sendToLibcSend"], True)

        for key, role in (("d18e", "_svctl_send_entry"), ("d18f", "libc_send_entry")):
            obs = a[key]
            self.assertEqual(obs["observedRole"], role)
            self.assertIs(obs["stable8ByteA1StatusRelation"], True)
            self.assertIs(obs["startDiffersOnStable8ByteA1Relation"], True)
            self.assertIs(obs["memory260StatusStable"], False)

    def test_interpretation_boundary_stays_closed(self):
        b = self.r["interpretationBoundary"]
        for key in (
            "digestValuesPublished",
            "rawPayloadPublished",
            "protocolEnumValuesAccepted",
            "packetFieldLayoutAccepted",
            "socketDescriptorValueAccepted",
            "sendLengthValueAccepted",
            "sendFlagsValueAccepted",
            "physicalRouterContact",
            "modifiedHilAuthorized",
            "responseReadEdgeInferred",
        ):
            self.assertIs(b[key], False, key)
        self.assertIs(b["requestLocalizationBranchClosedOnPass"], True)

if __name__ == "__main__":
    unittest.main()
