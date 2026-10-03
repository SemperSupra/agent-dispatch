import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1k_selector_ternary_operands.py"
SPEC = importlib.util.spec_from_file_location("d1k", SCRIPT)
d1k = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1k)


class D1kTests(unittest.TestCase):
    def test_selector_candidate_and_identifier_resolution(self):
        text = r'''
const char *fs0 = "filesystem";
const char *fs1 = "filesystem2";
void f(void) {
  new_name = (linux_fs_start == 0) ? fs0 : fs1;
}
'''
        recovery = d1k.recover_mapping(text)
        self.assertEqual(recovery["selectorBearingAssignmentCount"], 1)
        entry = recovery["decoded"][0]
        self.assertTrue(entry["ternaryRecognized"])
        self.assertTrue(entry["conditionNormalized"])
        self.assertEqual(entry["trueArm"]["safeIdentifier"], "fs0")
        self.assertEqual(entry["trueArm"]["resolvedDestination"], "filesystem")
        self.assertEqual(entry["falseArm"]["resolvedDestination"], "filesystem2")
        self.assertEqual(
            entry["normalizedCaseMapping"],
            {"0": "filesystem", "1": "filesystem2"},
        )

    def test_ambiguous_identifier_stays_unresolved(self):
        text = r'''
const char *fs0 = "filesystem";
void g(void) { fs0 = "other"; }
void f(void) {
  new_name = (linux_fs_start == 0) ? fs0 : "filesystem2";
}
'''
        entry = d1k.recover_mapping(text)["decoded"][0]
        self.assertIsNone(entry["trueArm"]["resolvedDestination"])
        self.assertIsNone(entry["normalizedCaseMapping"])

    def test_direct_string_arms_can_map(self):
        text = r'''
void f(void) {
  new_name = linux_fs_start ? "filesystem2" : "filesystem";
}
'''
        entry = d1k.recover_mapping(text)["decoded"][0]
        self.assertEqual(
            entry["normalizedCaseMapping"],
            {"0": "filesystem", "1": "filesystem2"},
        )

    def test_non_normalized_condition_remains_partial(self):
        text = r'''
void f(void) {
  new_name = (linux_fs_start > 7) ? "filesystem2" : "filesystem";
}
'''
        entry = d1k.recover_mapping(text)["decoded"][0]
        self.assertTrue(entry["ternaryRecognized"])
        self.assertFalse(entry["conditionNormalized"])
        self.assertIsNone(entry["normalizedCaseMapping"])

    def test_crosscheck_classification_requires_all_destinations(self):
        recovery = {
            "selectorBearingAssignmentCount": 1,
            "decoded": [{
                "normalizedCaseMapping": {"0": "filesystem", "1": "filesystem2"},
                "ternaryRecognized": True,
            }],
        }
        partial = [{"destination": "filesystem", "independentlyObserved": True}]
        full = [
            {"destination": "filesystem", "independentlyObserved": True},
            {"destination": "filesystem2", "independentlyObserved": True},
        ]
        self.assertEqual(
            d1k.classify(recovery, partial, []),
            "H0_D1K_SELECTOR_DESTINATION_MAPPING_CROSSCHECK_PARTIAL",
        )
        self.assertEqual(
            d1k.classify(recovery, full, []),
            "H0_D1K_SELECTOR_DESTINATION_MAPPING_CROSSCHECKED",
        )


if __name__ == "__main__":
    unittest.main()
