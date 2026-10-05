import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "evidence" / "fritz-e2-d19-response-role.json"

class FritzD19ResponseRoleTest(unittest.TestCase):
    def setUp(self):
        self.r = json.loads(DOC.read_text(encoding="utf-8"))

    def test_exact_classification(self):
        self.assertEqual(self.r["schemaVersion"], "fritz-e2-d19-response-role/v1")
        self.assertEqual(self.r["classification"], "E2_D19_SVCTL_READ_ENTRY_ROLE_EARNED")
        self.assertIs(self.r["oracleSatisfied"], True)

    def test_role_is_earned_from_accepted_caller_and_symbol_facts(self):
        f = self.r["acceptedFacts"]
        self.assertIs(f["libsvctl"]["svctlReadSymbolRecovered"], True)
        self.assertEqual(f["libsvctl"]["svctlReadFunctionBytes"], 188)
        self.assertIs(f["caller"]["svctlToSvctlReadCallsiteRecovered"], True)
        self.assertEqual(f["caller"]["svctlReadAcceptedCallsiteCount"], 1)

        role = self.r["earnedObservationRole"]
        self.assertEqual(role["symbol"], "_svctl_read")
        self.assertEqual(role["boundary"], "function_entry")
        self.assertEqual(
            set(role["allowedDimensions"]),
            {"hit_count", "argument_scalar_class", "bounded_pointed_memory_digest_relation"},
        )
        self.assertIs(role["requiresStatusRepeatStability"], True)
        self.assertIs(role["debuggerOnly"], True)
        self.assertIs(role["hostStraceExcluded"], True)
        self.assertIs(role["sameRunWireCaptureExcluded"], True)

    def test_d16_negative_is_preserved(self):
        c = self.r["acceptedFacts"]["calleeBoundary"]
        self.assertEqual(c["selectedLibcReadGotLoadCount"], 1)
        self.assertEqual(c["firstTransferClass"], "return_or_indirect_jump")
        self.assertIs(c["freshPostReturnReadReloadObserved"], False)
        self.assertIs(c["boundedCalleeT9PreservationProven"], False)
        self.assertIs(c["svctlReadToLibcReadEdgeAccepted"], False)

    def test_response_question_is_bounded(self):
        q = self.r["acceptedFacts"]["responseQuestion"]
        self.assertIs(q["statusResponsesEquivalent"], True)
        self.assertIs(q["startResponseDiffers"], True)
        self.assertIs(q["statusChanged"], False)
        self.assertIs(q["ctlmgrStarted"], False)

    def test_interpretation_boundary_stays_closed(self):
        b = self.r["interpretationBoundary"]
        for key in (
            "libcReadOwnershipInferred",
            "responsePayloadPublished",
            "responseFieldLayoutAccepted",
            "protocolEnumValuesAccepted",
            "payloadOffsetsAccepted",
            "rawPointersPublished",
            "rawMemoryPublished",
            "rawDigestValuesPublished",
            "returnRoleEarned",
            "additionalDownstreamRoleEarned",
            "physicalRouterContact",
            "modifiedHilAuthorized",
        ):
            self.assertIs(b[key], False, key)
        self.assertIs(b["typedNegativeStopsWithoutHeuristicWidening"], True)

if __name__ == "__main__":
    unittest.main()
