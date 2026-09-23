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

    def test_f1_kernel_is_exactly_pinned(self):
        self.assertEqual(
            rdte.KERNEL_OBJECT_KEY,
            "firecracker-ci/20260923-6f82ac4cf331-0/x86_64/vmlinux-6.18.48",
        )
        self.assertRegex(rdte.KERNEL_SHA256, r"^[0-9a-f]{64}$")
        self.assertNotIn("latest", rdte.KERNEL_URL.lower())

    def test_receipt_separates_portable_and_gha_evidence(self):
        receipt = rdte.make_receipt("F0")
        self.assertIn("portable_evidence", receipt)
        self.assertIn("gha_adapter_evidence", receipt)
        self.assertNotEqual(
            receipt["portable_evidence"],
            receipt["gha_adapter_evidence"],
        )

    def test_no_rung_can_claim_sovereign_readiness_by_default(self):
        for rung in ("F0", "F1", "F2", "F3"):
            receipt = rdte.make_receipt(rung)
            self.assertFalse(receipt["claims"]["sovereign_operational_ready"])
            self.assertFalse(receipt["claims"]["microvm_workload_supported"])

    def test_f0_cannot_claim_guest_readiness(self):
        receipt = rdte.make_receipt("F0")
        self.assertFalse(receipt["claims"]["guest_boot_supported"])
        self.assertEqual(receipt["portable_evidence"]["guest_boot"], "UNTESTED")

    def test_newc_builder_is_deterministic_and_contains_init(self):
        a = rdte.build_newc_single_file("init", b"abc")
        b = rdte.build_newc_single_file("init", b"abc")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith(b"070701"))
        self.assertIn(b"init\0", a)
        self.assertIn(b"TRAILER!!!\0", a)

    def test_f3_is_experiment_local_not_generic_workcell(self):
        self.assertEqual(rdte.F3_CAPSULE_SCHEMA, "firecracker-rdte-capsule/v0")
        self.assertNotIn("microvm-workcell", rdte.F3_CAPSULE_SCHEMA)
        receipt = rdte.make_receipt("F3")
        self.assertFalse(receipt["claims"]["experiment_capsule_supported"])
        self.assertFalse(receipt["claims"]["microvm_workload_supported"])
        self.assertFalse(receipt["claims"]["sovereign_operational_ready"])

    def test_f2_drive_contract_has_no_root_device(self):
        ro = rdte.f2_drive("input", Path("/tmp/input.ext4"), True)
        rw = rdte.f2_drive("output", Path("/tmp/output.ext4"), False)
        self.assertFalse(ro["is_root_device"])
        self.assertFalse(rw["is_root_device"])
        self.assertTrue(ro["is_read_only"])
        self.assertFalse(rw["is_read_only"])

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
            rc = rdte.run_f0(out)
            receipt = json.loads(out.read_text())
            self.assertEqual(rc, 0)
            self.assertEqual(receipt["result"], "SKIPPED_GUARDRAIL")
            self.assertFalse(receipt["claims"]["firecracker_acquisition_callable"])


if __name__ == "__main__":
    unittest.main()
