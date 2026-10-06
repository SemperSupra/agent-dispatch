import unittest

from scripts.truenas_compute_vm_probe import (
    ProbeError,
    legacy_owned_nic,
    legacy_vm_create_payload,
    native_vm_create_payload,
    normalize_system_version,
    owned_zvol_device,
    validate_modern_preconditions,
    validate_public_modern_preconditions,
    zvol_device_path,
)


class VmProbeContractTests(unittest.TestCase):
    def test_version_normalization(self):
        self.assertEqual(normalize_system_version("TrueNAS-25.10.7"),"25.10.7")

    def test_native_vm_defaults_are_stopped_safe_contract(self):
        p=native_vm_create_payload("rdtecomputevmv0")
        self.assertEqual(p["name"],"rdtecomputevmv0")
        self.assertFalse(p["autostart"])
        self.assertFalse(p["ensure_display_device"])
        self.assertEqual(p["bootloader"],"UEFI")
        self.assertFalse(p["trusted_platform_module"])
        self.assertFalse(p["enable_secure_boot"])

    def test_native_vm_name_matches_exact_trueNAS_contract(self):
        self.assertEqual(native_vm_create_payload("rdte_vm_v0")["name"], "rdte_vm_v0")
        for invalid in ("rdte-v0", "rdte vm v0", "rdte/v0"):
            with self.assertRaises(ProbeError):
                native_vm_create_payload(invalid)

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

    def test_zvol_readback_path_is_normalized(self):
        self.assertEqual(
            zvol_device_path("rdtepool/rdte vm v0"),
            "/dev/zvol/rdtepool/rdte+vm+v0",
        )

    def test_legacy_owned_nic_uses_observed_parent(self):
        d=legacy_owned_nic("rdte-v0-nic","enp1s0")
        self.assertEqual(d["name"],"rdte-v0-nic")
        self.assertEqual(d["dev_type"],"NIC")
        self.assertEqual(d["nic_type"],"MACVLAN")
        self.assertEqual(d["parent"],"enp1s0")

    def test_modern_preconditions_require_kvm_and_entitlement(self):
        ok=validate_modern_preconditions({"supported":True,"error":None},True)
        self.assertTrue(ok["license_active"])
        with self.assertRaises(ProbeError):
            validate_modern_preconditions({"supported":False,"error":"no kvm"},True)
        with self.assertRaises(ProbeError):
            validate_modern_preconditions({"supported":True,"error":None},False)
        with self.assertRaises(ProbeError):
            validate_modern_preconditions({},True)

    def test_beta3_public_entitlement_path_never_needs_private_license_method(self):
        community=validate_public_modern_preconditions(
            {"supported":True,"error":None},"COMMUNITY_EDITION",None
        )
        self.assertEqual(community["product_type"],"COMMUNITY_EDITION")
        enterprise=validate_public_modern_preconditions(
            {"supported":True,"error":None},"ENTERPRISE",True
        )
        self.assertTrue(enterprise["enterprise_vm_feature_enabled"])
        with self.assertRaises(ProbeError):
            validate_public_modern_preconditions(
                {"supported":True,"error":None},"ENTERPRISE",False
            )
        with self.assertRaises(ProbeError):
            validate_public_modern_preconditions(
                {"supported":False,"error":"no kvm"},"COMMUNITY_EDITION",None
            )


if __name__=="__main__":
    unittest.main()
