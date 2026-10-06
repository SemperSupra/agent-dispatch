import copy
import unittest

from scripts.windows_w1_runtime_oracle import (
    FIXTURE_ID,
    MEDIA_SHA256,
    NONCE_PREFIX,
    evaluate,
)


def accepted_receipt(platform: str):
    nonce = NONCE_PREFIX + "portablew1nonce20261006"
    return {
        "schema": "windows-w1-runtime-evidence/v1",
        "platform": platform,
        "source_profile_bound": True,
        "fixture": FIXTURE_ID,
        "media_sha256": MEDIA_SHA256,
        "resources": {
            "virtual_processors": 2,
            "memory_mib": 4096,
            "system_disk_gib": 64,
            "cpu_semantics": "host-passthrough",
            "install_storage_semantics": "inbox-driver-compatible-ahci-sata",
            "install_network_semantics": "inbox-driver-compatible-e1000",
        },
        "security": {
            "firmware": "UEFI",
            "secure_boot": True,
            "tpm_version": "2.0",
        },
        "seed": {
            "schema": "windows-w1-unattend-seed/v1",
            "volume_label": "ADW1SEED",
            "embedded_product_key": False,
            "embedded_password": False,
        },
        "guest_oracle": {
            "expected_nonce": nonce,
            "initial_nonce": nonce,
            "restart_nonce": nonce,
            "initial_external": True,
            "restart_external": True,
        },
        "lifecycle": {
            "install_completed": True,
            "restart_completed": True,
            "install_media_absent": True,
            "seed_media_absent": True,
            "system_disk_booted": True,
        },
        "cleanup": {
            "vm_absent": True,
            "system_storage_absent": True,
            "staged_media_absent": True,
            "owned_residue_absent": True,
        },
        "provider_evidence": {"native_id": "opaque-provider-specific-id"},
    }


class WindowsW1RuntimeOracleTests(unittest.TestCase):
    def test_same_portable_oracle_accepts_both_backends(self):
        tn = evaluate(accepted_receipt("truenas"))
        pve = evaluate(accepted_receipt("proxmox"))
        self.assertEqual(tn["classification"], "SUPPORTED")
        self.assertEqual(pve["classification"], "SUPPORTED")
        self.assertTrue(tn["oracleSatisfied"])
        self.assertTrue(pve["oracleSatisfied"])
        self.assertEqual(tn["checks"], pve["checks"])

    def test_restart_nonce_is_independent_required_oracle(self):
        r = accepted_receipt("truenas")
        r["guest_oracle"]["restart_nonce"] = NONCE_PREFIX + "wrong"
        result = evaluate(r)
        self.assertEqual(result["classification"], "ORACLE_FAILURE")
        self.assertIn("restart_guest_nonce", result["failures"])
        self.assertNotIn("initial_guest_nonce", result["failures"])

    def test_media_detach_and_system_disk_boot_are_required(self):
        r = accepted_receipt("proxmox")
        r["lifecycle"]["seed_media_absent"] = False
        r["lifecycle"]["system_disk_booted"] = False
        result = evaluate(r)
        self.assertFalse(result["oracleSatisfied"])
        self.assertIn("seed_media_absent", result["failures"])
        self.assertIn("system_disk_booted", result["failures"])

    def test_cleanup_is_not_inferred_from_vm_absence(self):
        r = accepted_receipt("truenas")
        r["cleanup"]["system_storage_absent"] = False
        result = evaluate(r)
        self.assertFalse(result["oracleSatisfied"])
        self.assertTrue(result["checks"]["vm_absent"])
        self.assertFalse(result["checks"]["system_storage_absent"])

    def test_platform_specific_evidence_does_not_change_portable_acceptance(self):
        a = accepted_receipt("truenas")
        b = copy.deepcopy(a)
        a["provider_evidence"] = {"job_id": 123, "zvol": "pool/w1"}
        b["provider_evidence"] = {"job_id": 999, "zvol": "other/w1"}
        self.assertEqual(evaluate(a)["checks"], evaluate(b)["checks"])

    def test_unknown_platform_and_unbound_source_fail_closed(self):
        r = accepted_receipt("truenas")
        r["platform"] = "hyperv"
        r["source_profile_bound"] = False
        result = evaluate(r)
        self.assertIn("platform", result["failures"])
        self.assertIn("source_profile_bound", result["failures"])


if __name__ == "__main__":
    unittest.main()
