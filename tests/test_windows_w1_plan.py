import copy
import unittest

from scripts.windows_w1_plan import (
    DISK_BYTES,
    WINDOWS_FIXTURE,
    WINDOWS_SHA256,
    WindowsPlanError,
    load_profile,
    portable_intent,
    provider_plan,
)


class WindowsW1PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile()

    def test_portable_intent_is_exact_and_provider_neutral(self):
        intent = portable_intent(self.profile)
        self.assertEqual(intent["fixture"], WINDOWS_FIXTURE)
        self.assertEqual(intent["source"]["sha256"], WINDOWS_SHA256)
        self.assertEqual(intent["compute"], {"vcpus": 2, "memory_mib": 4096})
        self.assertEqual(intent["storage"]["system_disk_bytes"], DISK_BYTES)
        self.assertEqual(
            intent["firmware"],
            {"uefi": True, "machine": "q35", "secure_boot": True, "tpm": "2.0"},
        )
        self.assertFalse(intent["cpu"]["nested_virtualization_required_for_w1"])
        self.assertNotIn("product_key", str(intent).lower())

    def test_truenas_lowering_preserves_windows_security_intent(self):
        plan = provider_plan(self.profile, "truenas", "26.0.0-BETA.3")
        lower = plan["lowering"]
        create = lower["vm_create"]
        self.assertEqual(lower["adapter"], "truenas-vm-libvirt")
        self.assertEqual(create["cpu_mode"], "HOST-PASSTHROUGH")
        self.assertEqual(create["bootloader"], "UEFI")
        self.assertEqual(create["bootloader_ovmf"], "OVMF_CODE_4M.secboot.fd")
        self.assertEqual(create["machine_type"], "q35")
        self.assertTrue(create["enable_secure_boot"])
        self.assertTrue(create["trusted_platform_module"])
        self.assertTrue(create["hyperv_enlightenments"])
        self.assertEqual(lower["runtime_status"], "OPEN")
        self.assertFalse(lower["mutation_authorized"])

    def test_pve_lowering_preserves_windows_security_intent(self):
        plan = provider_plan(self.profile, "proxmox", "9.2-1", vmid=9301)
        lower = plan["lowering"]
        fields = lower["create_fields"]
        self.assertEqual(lower["adapter"], "proxmox-vm-rest")
        self.assertEqual(fields["cpu"], "host")
        self.assertEqual(fields["bios"], "ovmf")
        self.assertEqual(fields["machine"], "q35")
        self.assertEqual(fields["ostype"], "win11")
        self.assertTrue(lower["storage_intent"]["efi"]["pre_enrolled_keys"])
        self.assertEqual(lower["storage_intent"]["tpm"]["version"], "v2.0")
        self.assertEqual(lower["runtime_status"], "OPEN")
        self.assertFalse(lower["mutation_authorized"])

    def test_true_nas_name_guard_fails_closed(self):
        with self.assertRaises(WindowsPlanError):
            provider_plan(self.profile, "truenas", "26.0.0-BETA.3", name="bad-name")

    def test_runtime_claim_drift_fails_closed(self):
        profile = copy.deepcopy(self.profile)
        profile["proxmox"]["9.2-1"]["windows11"]["runtime_status"] = "PASS"
        with self.assertRaises(WindowsPlanError):
            provider_plan(profile, "proxmox", "9.2-1")

    def test_unsupported_target_fails_closed(self):
        with self.assertRaises(WindowsPlanError):
            provider_plan(self.profile, "proxmox", "9.1-1")


if __name__ == "__main__":
    unittest.main()
