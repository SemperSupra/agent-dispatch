import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import runner_optimization_benchmarks as rob

class RunnerOptimizationBenchmarksTest(unittest.TestCase):
    def test_run_benchmarks_emits_valid_schema(self):
        receipt = rob.run_benchmarks("test-runner")
        self.assertEqual(receipt["schema"], rob.SCHEMA)
        self.assertEqual(receipt["runner_label"], "test-runner")
        self.assertIn("status", receipt)
        self.assertIn("compute_jitter_benchmark", receipt)
        self.assertIn("ramdisk_benchmark", receipt)
        self.assertTrue(receipt["compute_jitter_benchmark"]["jitter_acceptable"])

if __name__ == "__main__":
    unittest.main()
