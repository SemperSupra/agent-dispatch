import unittest

from scripts.truenas_compute_vm_probe import (
    ProbeError,
    legacy_vm_create_payload,
    native_vm_create_payload,
    normalize_system_version,
    owned_zvol_device,
)


class VmProbeContractTests(unittest.TestCase):
    def test_version_normalization(self):
        self.assertEqual(normalize_system_version("TrueNAS-25.10.7"),"25.10.7")

    def test_native_vm_defaults_are_stopped_safe_contract(self):
        p=native_vm_create_payload("rdte-v0")
        self.assertEqual(p["name"],"rdte-v0")
        self.assertFalse(p["autostart"])
        self.assertFalse(p["ensure_display_device"])
        self.assertEqual(p["bootloader"],"UEFI")
        self.assertFalse(p["trusted_platform_module"])
        self.assertFalse(p["enable_secure_boot"])

    def test_legacy_vm_uses_vm_instance_type(self):
        p=legacy_vm_create_payload("rdte-v0","ubuntu/24.04")
        self.assertEqual(p["instance_type"],"VM")
        self.assertEqual(p["source_type"],"IMAGE")
        self.assertFalse(p["autostart"])

    def test_legacy_vm_requires_image(self):
        with self.assertRaises(ProbeError):
            legacy_vm_create_payload("rdte-v0","")

    def test_owned_zvol_device_is_explicit_and_nonbooting(self):
        d=owned_zvol_device(7,"rdtepool/rdte-compute-vm-v0",2*1024*1024*1024)
        self.assertEqual(d["vm"],7)
        self.assertTrue(d["attributes"]["create_zvol"])
        self.assertEqual(d["attributes"]["zvol_name"],"rdtepool/rdte-compute-vm-v0")
        self.assertFalse(d["attributes"]["boot"])
        self.assertEqual(d["order"],1000)

    def test_zvol_requires_owned_parent_name(self):
        with self.assertRaises(ProbeError):
            owned_zvol_device(7,"bare-name",1024)


if __name__=="__main__":
    unittest.main()
