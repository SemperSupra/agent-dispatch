import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_receipt_diff",
    ROOT / "scripts" / "github_runner_receipt_diff.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class RunnerReceiptDiffTests(unittest.TestCase):
    def receipt(self, oracle=True, image="a"):
        return {
            "provenance": {
                "requested_label": "runner",
                "image_version": image,
                "probe_version": "p",
            },
            "resources": {"cpu": {"logical_processors": 4}, "memory": {"total_bytes": 16}},
            "capabilities": [{
                "name": "x",
                "observed": True,
                "installed": True,
                "callable": True,
                "exercised": True,
                "oracleSatisfied": oracle,
                "classification": "SUPPORTED" if oracle else "ORACLE_FAILURE",
            }],
        }

    def test_oracle_regression_is_explicit(self):
        result = MOD.compare(self.receipt(True), self.receipt(False, "b"))
        self.assertEqual(result["capability_changes"][0]["kind"], "oracle-regression")

    def test_no_scalar_score(self):
        result = MOD.compare(self.receipt(True), self.receipt(True, "b"))
        self.assertNotIn("score", result)


if __name__ == "__main__":
    unittest.main()
