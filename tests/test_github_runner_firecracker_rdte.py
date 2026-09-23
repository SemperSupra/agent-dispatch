import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.github_runner_firecracker_rdte as rdte


class FirecrackerRdteContractTests(unittest.TestCase):
    def test_release_is_exactly_pinned(self):
        self.assertEqual(rdte.FIRECRACKER_VERSION, "1.17.0")
        self.assertRegex(rdte.FIRECRACKER_SHA256, r"^[0-9a-f]{64}$")
        self.assertIn("/v1.17.0/", rdte.FIRECRACKER_URL)

    def test_receipt_separates_portable_and_gha_evidence(self):
        receipt = rdte.make_receipt()
        self.assertIn("portable_evidence", receipt)
        self.assertIn("gha_adapter_evidence", receipt)
        self.assertNotEqual(
            receipt["portable_evidence"],
            receipt["gha_adapter_evidence"],
        )

    def test_f0_cannot_claim_guest_or_sovereign_readiness(self):
        receipt = rdte.make_receipt()
        self.assertFalse(receipt["claims"]["guest_boot_supported"])
        self.assertFalse(receipt["claims"]["microvm_workload_supported"])
        self.assertFalse(receipt["claims"]["sovereign_operational_ready"])
        self.assertEqual(receipt["portable_evidence"]["guest_boot"], "UNTESTED")

    def test_sha256_helper(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x"
            p.write_bytes(b"abc")
            self.assertEqual(
                rdte.sha256_file(p),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_non_x86_is_guardrail_skip_without_promotion(self):
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(rdte.platform, "machine", return_value="aarch64"), \
             mock.patch.object(rdte, "observe_kvm", return_value={"exists": False}):
            out = Path(td) / "receipt.json"
            rc = rdte.run(out)
            receipt = json.loads(out.read_text())
            self.assertEqual(rc, 0)
            self.assertEqual(receipt["result"], "SKIPPED_GUARDRAIL")
            self.assertFalse(receipt["claims"]["firecracker_acquisition_callable"])


if __name__ == "__main__":
    unittest.main()
