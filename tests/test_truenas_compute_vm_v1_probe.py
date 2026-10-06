import unittest

from scripts.truenas_compute_vm_v1_probe import (
    PINNED_CIRROS_SHA256,
    multipart_upload_body,
    plan,
    raw_boot_device,
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

    def test_devices_use_public_raw_and_cdrom_shapes(self):
        raw = raw_boot_device(7, "/mnt/rdtepool/rdtev1stage/cirros.raw")
        self.assertEqual(raw["attributes"]["dtype"], "RAW")
        self.assertTrue(raw["attributes"]["exists"])
        self.assertTrue(raw["attributes"]["boot"])
        self.assertEqual(raw["attributes"]["type"], "VIRTIO")
        cd = seed_cdrom_device(7, "/mnt/rdtepool/rdtev1stage/seed.iso")
        self.assertEqual(cd["attributes"], {"dtype": "CDROM", "path": "/mnt/rdtepool/rdtev1stage/seed.iso"})

    def test_plan_keeps_v1_claim_narrow(self):
        p = plan("rdtepool", "rdtecomputevmv1", "rep001nonceABCDEF12")
        self.assertEqual(p["schema"], "truenas-compute-vm-v1-plan/v1")
        self.assertEqual(p["oracle"]["surface"], "/websocket/shell")
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


if __name__ == "__main__":
    unittest.main()
