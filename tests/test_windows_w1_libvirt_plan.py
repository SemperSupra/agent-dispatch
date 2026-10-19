import copy
import pathlib
import unittest

from scripts.compute_guest_profile_contract import load, validate
from scripts.windows_w1_libvirt_plan import libvirt_w1_plan, LibvirtW1PlanError, MEDIA_SHA256, MEDIA_SIZE


UUID = "c31d4df2-9ab1-4ea7-b317-75b9c633b9b1"
HEX = UUID.replace("-", "")


def good_observation():
    return {
        "owned_root": "/var/lib/libvirt/images/ad-w1-" + HEX,
        "libvirt_uri": "qemu:///system",
        "kvm_vcpu_exercised": True,
        "host_passthrough_supported": True,
        "secureboot_firmware_observed": True,
        "enrolled_keys_observed": True,
        "swtpm2_startup_exercised": True,
        "owned_isolated_network_observed": True,
        "domain_uuid_absent": True,
        "owned_root_absent": True,
        "installer_media_digest_verified": True,
        "unattended_seed_secret_free": True,
        "windows_wipe_target_is_single_run_owned_disk": True,
        "installer_media_sha256": MEDIA_SHA256,
        "installer_media_size_bytes": MEDIA_SIZE,
        "network": "ad-w1-" + HEX,
        "unattended_seed_sha256": "f" * 64,
    }


class WindowsW1LibvirtPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load(pathlib.Path("config/compute-guest-profiles.json"))
        validate(cls.profile)

    def test_plan_reuses_exact_portable_w1_semantics_without_admission(self):
        plan = libvirt_w1_plan(self.profile, good_observation(), UUID)
        self.assertEqual(plan["platform"], "libvirt-kvm")
        self.assertEqual(plan["vm_create"]["domain_type"], "kvm")
        self.assertEqual(plan["vm_create"]["cpu"], "host-passthrough")
        self.assertEqual(plan["vm_create"]["machine"], "q35")
        self.assertTrue(plan["vm_create"]["secure_boot"])
        self.assertTrue(plan["vm_create"]["enrolled_keys"])
        self.assertEqual(plan["vm_create"]["tpm_backend"], "swtpm-emulator-v2")
        self.assertEqual(plan["vm_create"]["storage"]["bus"], "sata")
        self.assertEqual(plan["vm_create"]["network"]["model"], "e1000")
        self.assertEqual(plan["vm_create"]["serial"]["device"], "COM1")
        self.assertEqual(plan["vm_create"]["installer_cdrom"]["sha256"], MEDIA_SHA256)
        self.assertEqual(plan["vm_create"]["seed_cdrom"]["volume_label"], "ADW1SEED")
        self.assertFalse(plan["mutation_authorized"])
        self.assertFalse(plan["windows_guest_qualified"])
        self.assertFalse(plan["winbot_guest_qualified"])

    def test_all_unknown_and_false_capabilities_refused(self):
        for key in ("kvm_vcpu_exercised", "host_passthrough_supported",
                    "secureboot_firmware_observed", "enrolled_keys_observed",
                    "swtpm2_startup_exercised", "owned_isolated_network_observed",
                    "domain_uuid_absent", "owned_root_absent",
                    "installer_media_digest_verified", "unattended_seed_secret_free",
                    "windows_wipe_target_is_single_run_owned_disk"):
            for value in (None, False):
                obs = good_observation()
                obs[key] = value
                with self.subTest(field=key, value=value), self.assertRaises(LibvirtW1PlanError):
                    libvirt_w1_plan(self.profile, obs, UUID)
            obs = good_observation()
            del obs[key]
            with self.subTest(field=key, value="missing"), self.assertRaises(LibvirtW1PlanError):
                libvirt_w1_plan(self.profile, obs, UUID)

    def test_media_sha_size_and_seed_digest_are_observed_not_assumed(self):
        for key, value in (
            ("installer_media_sha256", "0" * 64),
            ("installer_media_size_bytes", 7),
            ("unattended_seed_sha256", "not-a-hash"),
        ):
            obs = good_observation()
            obs[key] = value
            with self.subTest(field=key), self.assertRaises(LibvirtW1PlanError):
                libvirt_w1_plan(self.profile, obs, UUID)

    def test_preexisting_resource_wrong_network_and_unowned_path_refused(self):
        for key, value in (
            ("domain_uuid_absent", False),
            ("owned_root_absent", False),
            ("network", "default"),
            ("owned_root", "/var/lib/libvirt/images"),
            ("libvirt_uri", "qemu:///session"),
        ):
            obs = good_observation()
            obs[key] = value
            with self.subTest(field=key), self.assertRaises(LibvirtW1PlanError):
                libvirt_w1_plan(self.profile, obs, UUID)
        for bad_uuid in ("not-uuid", "00000000-0000-0000-0000-000000000000", "C31D4DF2-9AB1-4EA7-B317-75B9C633B9B1"):
            with self.subTest(uuid=bad_uuid), self.assertRaises(LibvirtW1PlanError):
                libvirt_w1_plan(self.profile, good_observation(), bad_uuid)

    def test_portable_w1_contract_matches_native_trueNAS_and_proxmox(self):
        from scripts.windows_w1_native_plan import truenas_plan, proxmox_plan
        base = libvirt_w1_plan(self.profile, good_observation(), UUID)["portable_intent"]
        tn = truenas_plan(self.profile, pool="rdtepool",
                          iso_path="/mnt/rdtepool/windows/install.iso",
                          seed_path="/mnt/rdtepool/windows/adw1seed.iso",
                          bridge="br0")["portable_intent"]
        pve = proxmox_plan(self.profile, vmid=9301, storage="local-lvm",
                           iso_volume="local:iso/install.iso",
                           seed_volume="local:iso/adw1seed.iso",
                           bridge="vmbr0")["portable_intent"]
        self.assertEqual(base, tn)
        self.assertEqual(base, pve)


if __name__ == "__main__":
    unittest.main()
