import importlib.util
import pathlib
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "firecracker_lifecycle_timing",
    ROOT / "scripts" / "firecracker_lifecycle_timing.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class LifecycleTimingTests(unittest.TestCase):
    def test_stage_records_scope_and_monotonic_duration(self):
        timer = MOD.LifecycleTimer()
        with timer.stage("portable-step", "portable"):
            time.sleep(0.002)
        receipt = timer.receipt()
        self.assertEqual(receipt["stages"][0]["name"], "portable-step")
        self.assertEqual(receipt["stages"][0]["scope"], "portable")
        self.assertGreaterEqual(receipt["stages"][0]["elapsed_ms"], 0)
        self.assertGreaterEqual(receipt["total_elapsed_ms"], receipt["stages"][0]["elapsed_ms"])

    def test_add_accepts_derived_guest_timing(self):
        timer = MOD.LifecycleTimer()
        timer.add("guest-kernel-to-init", "portable", 512.5)
        receipt = timer.receipt()
        self.assertEqual(receipt["stages"][0]["elapsed_ms"], 512.5)


if __name__ == "__main__":
    unittest.main()
