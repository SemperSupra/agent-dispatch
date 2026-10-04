import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1q_get_name_argument_provenance.py"
SPEC = importlib.util.spec_from_file_location("d1q", SCRIPT)
d1q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1q)


class D1qTests(unittest.TestCase):
    def test_function_parameter_provenance(self):
        text = r"""
struct mtd_entry *nametable;
static int caller(struct mtd_entry *mtd_entry) {
    return get_name(*(mtd_entry - nametable));
}
"""
        a = d1q.analyze_target(text)
        self.assertEqual(a["getNameNametableCallsiteCount"], 1)
        call = a["calls"][0]
        self.assertEqual(call["argumentIndex"], 0)
        self.assertEqual(call["enclosingFunction"]["name"], "caller")
        self.assertIn("dereference", call["argumentSkeleton"]["operatorClasses"])
        self.assertIn("arithmetic", call["argumentSkeleton"]["operatorClasses"])
        rel = [x for x in call["trackedIdentifiers"] if x["name"] == "mtd_entry"][0]
        self.assertEqual(rel["relation"], "function_parameter")
        self.assertEqual(
            d1q.classify(a),
            "H0_D1Q_GET_NAME_LOCAL_PROVENANCE_RECOVERED",
        )

    def test_nearest_lexical_assignment_candidate_is_sanitized(self):
        text = r"""
struct mtd_entry *nametable;
static int caller(void) {
    struct mtd_entry *entry;
    entry = choose_entry("secret");
    return get_name(*(entry - nametable));
}
"""
        a = d1q.analyze_target(text)
        call = a["calls"][0]
        rel = [x for x in call["trackedIdentifiers"] if x["name"] == "entry"][0]
        self.assertEqual(rel["relation"], "nearest_lexical_assignment_candidate")
        self.assertEqual(rel["assignmentCandidateCount"], 1)
        self.assertEqual(rel["nearestAssignmentRhs"]["rootCallIdentifier"], "choose_entry")
        self.assertNotIn("secret", repr(rel))

    def test_get_name_definition_is_not_callsite(self):
        text = r"""
struct mtd_entry *nametable;
static const char *get_name(struct mtd_entry *nametable) {
    return nametable->urlader_name;
}
"""
        a = d1q.analyze_target(text)
        self.assertEqual(a["getNameNametableCallsiteCount"], 0)
        self.assertEqual(a["localGetNameDefinitionCount"], 1)
        self.assertEqual(
            d1q.classify(a),
            "H0_D1Q_GET_NAME_EDGE_NOT_REPRODUCED",
        )

    def test_multiple_calls_type_ambiguity(self):
        text = r"""
struct mtd_entry *nametable;
static int caller(struct mtd_entry *a, struct mtd_entry *b) {
    get_name(*(a - nametable));
    get_name(*(b - nametable));
    return 0;
}
"""
        a = d1q.analyze_target(text)
        self.assertEqual(a["getNameNametableCallsiteCount"], 2)
        self.assertEqual(
            d1q.classify(a),
            "H0_D1Q_GET_NAME_ARGUMENT_AMBIGUOUS",
        )

    def test_interpretation_boundary_contract(self):
        self.assertEqual(
            d1q.INTERPRETATION_BOUNDARY,
            {
                "d1pGetNameHypothesisTested": True,
                "safeIdentifierAndOperatorClassesOnly": True,
                "functionParameterBindingsAccepted": True,
                "nearestLexicalAssignmentIsCandidateOnly": True,
                "controlFlowExecutionAccepted": False,
                "sourceSnippetsAccepted": False,
                "arbitraryStringLiteralsAccepted": False,
                "destinationNamesAccepted": False,
                "numericFlashOffsetsAccepted": False,
                "inactiveSlotSafetyAccepted": False,
                "rollbackSafetyAccepted": False,
                "bootabilityAccepted": False,
                "modifiedHilAuthorized": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
