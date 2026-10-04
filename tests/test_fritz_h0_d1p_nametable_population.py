import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1p_nametable_population.py"
SPEC = importlib.util.spec_from_file_location("d1p", SCRIPT)
d1p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1p)


class D1pTests(unittest.TestCase):
    def test_pointer_declaration_and_direct_assignment(self):
        text = r'''
struct mtd_entry *nametable;
void init(void) {
  nametable = build_table(source);
}
'''
        a = d1p.analyze_target(text)
        self.assertEqual(a["declaration"]["candidateCount"], 1)
        self.assertEqual(a["declaration"]["candidates"][0]["pointerDepth"], 1)
        self.assertEqual(a["derived"]["directAssignmentCount"], 1)
        rhs = a["directAssignments"][0]["rhs"]
        self.assertEqual(rhs["rootCallIdentifier"], "build_table")
        self.assertIn("call", rhs["operatorClasses"])

    def test_downstream_comparison_is_not_assignment(self):
        text = r'''
struct mtd_entry *nametable;
void f(void) {
  if (nametable == other) use(nametable);
}
'''
        a = d1p.analyze_target(text)
        self.assertEqual(a["derived"]["directAssignmentCount"], 0)
        self.assertEqual(a["derived"]["callEdgeCount"], 1)
        self.assertEqual(a["callEdges"][0]["callIdentifier"], "use")

    def test_member_write_is_sanitized(self):
        text = r'''
struct mtd_entry nametable[2];
void f(int i) {
  nametable[i].runtime_name_0 = make_name(i, "secret");
}
'''
        a = d1p.analyze_target(text)
        self.assertTrue(a["declaration"]["candidates"][0]["arrayDeclarator"])
        self.assertEqual(a["derived"]["memberWriteCount"], 1)
        w = a["memberWrites"][0]
        self.assertEqual(w["field"], "runtime_name_0")
        self.assertEqual(w["rhs"]["rootCallIdentifier"], "make_name")
        self.assertNotIn("secret", repr(w))

    def test_call_argument_indexes_only(self):
        text = r'''
struct mtd_entry *nametable;
void f(void) {
  populate(ctx, &nametable, 7);
}
'''
        a = d1p.analyze_target(text)
        self.assertEqual(a["derived"]["callEdgeCount"], 1)
        e = a["callEdges"][0]
        self.assertEqual(e["callIdentifier"], "populate")
        self.assertEqual(e["nametableArgumentIndexes"], [1])
        self.assertIn("address_of", e["argumentSkeletons"][0]["operatorClasses"])

    def test_classification_prefers_direct_assignment(self):
        a = {
            "derived": {
                "directAssignmentCount": 1,
                "memberWriteCount": 2,
                "callEdgeCount": 3,
            }
        }
        self.assertEqual(
            d1p.classify(a),
            "H0_D1P_DIRECT_ASSIGNMENT_PRODUCER_LOCATED",
        )


    def test_interpretation_boundary_contract(self):
        self.assertEqual(
            d1p.INTERPRETATION_BOUNDARY,
            {
                "declarationShapeAccepted": True,
                "assignmentAndCallShapesAreCandidateEvidenceOnly": True,
                "safeIdentifiersAndOperatorClassesOnly": True,
                "sourceSnippetsAccepted": False,
                "arbitraryStringLiteralsAccepted": False,
                "numericFlashOffsetsAccepted": False,
                "inactiveSlotSafetyAccepted": False,
                "rollbackSafetyAccepted": False,
                "modifiedHilAuthorized": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
