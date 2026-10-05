import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_d19_svctl_read_response.py"
SPEC = importlib.util.spec_from_file_location("d19b", SCRIPT)
d19b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d19b)

class D19bTests(unittest.TestCase):
    def test_merged_role_receipt_is_bounded(self):
        r = d19b.load_role()
        self.assertEqual(r["classification"], "E2_D19_SVCTL_READ_ENTRY_ROLE_EARNED")
        self.assertEqual(r["earnedObservationRole"]["symbol"], "_svctl_read")
        self.assertEqual(r["earnedObservationRole"]["boundary"], "function_entry")
        self.assertFalse(r["interpretationBoundary"]["libcReadOwnershipInferred"])
        self.assertFalse(r["interpretationBoundary"]["returnRoleEarned"])

    def test_classifier(self):
        ready = {
            "allCallsInstrumentationReady": True,
            "allExpectedTargetHits": True,
            "stableDimensionDiscriminatorCount": 0,
            "unstableStatusDimensionCount": 0,
        }
        self.assertEqual(
            d19b.classify(ready),
            "E2_D19B_SVCTL_READ_NO_RUNTIME_DISCRIMINATOR",
        )
        ready["stableDimensionDiscriminatorCount"] = 1
        self.assertEqual(
            d19b.classify(ready),
            "E2_D19B_SVCTL_READ_STABLE_RESPONSE_DISCRIMINATOR_FOUND",
        )
        ready["stableDimensionDiscriminatorCount"] = 0
        ready["unstableStatusDimensionCount"] = 1
        self.assertEqual(
            d19b.classify(ready),
            "E2_D19B_SVCTL_READ_UNSTABLE_STATUS_NO_DISCRIMINATOR",
        )
        ready["allExpectedTargetHits"] = False
        self.assertEqual(
            d19b.classify(ready),
            "E2_D19B_SVCTL_READ_INSTRUMENTATION_INCOMPLETE",
        )

    def test_parser_target_is_svctl_read_only(self):
        raw = (
            'FRITZOBS:{"target":"_svctl_read","args":{"a0":{},"a1":{},"a2":{},"a3":{}}}\n'
            'FRITZOBS:{"target":"read","args":{"a0":{},"a1":{},"a2":{},"a3":{}}}\n'
        )
        obs = d19b.d18.parse_gdb_observations(raw, d19b.TARGETS)
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0]["target"], "_svctl_read")

if __name__ == "__main__":
    unittest.main()
