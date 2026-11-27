import unittest
from pathlib import Path

from scripts.truenas_compute_vm_v1_probe import (
    PINNED_CIRROS_SHA256,
    multipart_upload_body,
    plan,
    zvol_boot_device,
    finalize_v1_receipt,
    seed_cdrom_device,
    stage_paths,
)


class TrueNASVmV1ProbeTests(unittest.TestCase):
    def test_pinned_cirros_digest(self):
        self.assertEqual(
            PINNED_CIRROS_SHA256,
            "7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b",
        )

    def test_stage_paths_are_owned_under_pool(self):
        paths = stage_paths("rdtepool")
        self.assertEqual(paths["dataset"], "rdtepool/rdtev1stage")
        self.assertTrue(paths["raw_image"].startswith("/mnt/rdtepool/rdtev1stage/"))
        self.assertTrue(paths["seed_iso"].endswith("/seed.iso"))
        self.assertEqual(paths["boot_zvol"], "rdtepool/rdtev1boot")
        self.assertEqual(paths["boot_zvol_path"], "/dev/zvol/rdtepool/rdtev1boot")

    def test_devices_use_owned_zvol_disk_and_public_cdrom_shapes(self):
        boot = zvol_boot_device(7, "rdtepool/rdtev1boot")
        self.assertEqual(boot["attributes"]["dtype"], "DISK")
        self.assertIsNone(boot["attributes"]["path"])
        self.assertTrue(boot["attributes"]["create_zvol"])
        self.assertEqual(boot["attributes"]["zvol_name"], "rdtepool/rdtev1boot")
        self.assertEqual(boot["attributes"]["zvol_volsize"], 1024 * 1024 * 1024)
        self.assertEqual(boot["attributes"]["type"], "VIRTIO")
        self.assertEqual(boot["order"], 100)
        cd = seed_cdrom_device(7, "/mnt/rdtepool/rdtev1stage/seed.iso")
        self.assertEqual(cd["attributes"], {"dtype": "CDROM", "path": "/mnt/rdtepool/rdtev1stage/seed.iso"})
        self.assertEqual(cd["order"], 1000)

    def test_plan_keeps_v1_claim_narrow(self):
        p = plan("rdtepool", "rdtecomputevmv1", "rep001nonceABCDEF12")
        self.assertEqual(p["schema"], "truenas-compute-vm-v1-plan/v1")
        self.assertEqual(p["oracle"]["surface"], "/websocket/shell")
        self.assertEqual(p["devices"][0]["attributes"]["dtype"], "DISK")
        self.assertEqual(p["media_lowering"]["method"], "vm.device.convert")
        self.assertEqual(p["media_lowering"]["source"], p["staging"]["raw_image"])
        self.assertEqual(p["media_lowering"]["destination"], p["staging"]["boot_zvol_path"])
        self.assertNotIn('"dtype": "RAW"', str(p))
        self.assertNotIn("firecracker", str(p).lower())
        self.assertNotIn("nested-kvm", str(p).lower())

    def test_upload_matches_trueNAS_filesystem_put_form(self):
        body = multipart_upload_body(
            "/mnt/rdtepool/rdtev1stage/seed.iso",
            "seed.iso",
            b"abc",
            "boundary",
        )
        self.assertIn(b'"method":"filesystem.put"', body)
        self.assertIn(b'"params":["/mnt/rdtepool/rdtev1stage/seed.iso"]', body)
        self.assertIn(b'name="file"; filename="seed.iso"', body)
        self.assertTrue(body.endswith(b"--boundary--\r\n"))



    def test_outer_shell_reducer_requires_all_cleanup_predicates(self):
        source = (
            Path(__file__).resolve().parents[1] / "scripts" / "gha_kvm_truenas_rdte.sh"
        ).read_text(encoding="utf-8")
        start = source.index('elif [[ "$COMPUTE_FIXTURE" == "vm-v1" ]]; then', source.index("COMPUTE_RESULT_JSON"))
        end = source.index('write_receipt SUPPORTED true compute-vm-v1', start)
        reducer = source[start:end]
        for key in (
            "attempted",
            "vm_absent",
            "boot_zvol_absent",
            "staging_dataset_absent",
            "zero_residue",
        ):
            self.assertIn(f'cleanup.get("{key}") is True', reducer)

    def test_final_oracle_requires_guest_nonce_and_all_cleanup_absence(self):
        base = {
            "classification": "SUPPORTED",
            "oracleSatisfied": True,
            "v1_oracle_satisfied": True,
            "guest_oracle": {"classification": "SUPPORTED", "oracleSatisfied": True},
            "cleanup": {
                "attempted": True,
                "vm_absent": True,
                "boot_zvol_absent": True,
                "staging_dataset_absent": True,
            },
        }
        import copy
        accepted = finalize_v1_receipt(copy.deepcopy(base))
        self.assertTrue(accepted["oracleSatisfied"])
        self.assertTrue(accepted["v1_oracle_satisfied"])
        self.assertTrue(accepted["cleanup"]["zero_residue"])

        for missing in ("vm_absent", "boot_zvol_absent", "staging_dataset_absent", "attempted"):
            receipt = copy.deepcopy(base)
            receipt["cleanup"][missing] = False
            rejected = finalize_v1_receipt(receipt)
            self.assertFalse(rejected["oracleSatisfied"], missing)
            self.assertFalse(rejected["v1_oracle_satisfied"], missing)
            self.assertEqual(rejected["classification"], "ORACLE_FAILURE")
            self.assertFalse(rejected["cleanup"]["zero_residue"])
            self.assertTrue(rejected["guest_nonce_verified"])

        missing_cleanup = copy.deepcopy(base)
        missing_cleanup.pop("cleanup")
        rejected = finalize_v1_receipt(missing_cleanup)
        self.assertFalse(rejected["oracleSatisfied"])
        self.assertFalse(rejected["cleanup"]["zero_residue"])

        no_guest = copy.deepcopy(base)
        no_guest["guest_oracle"]["oracleSatisfied"] = False
        rejected = finalize_v1_receipt(no_guest)
        self.assertFalse(rejected["oracleSatisfied"])
        self.assertFalse(rejected["guest_nonce_verified"])
        self.assertEqual(rejected["classification"], "ORACLE_FAILURE")


if __name__ == "__main__":
    unittest.main()
