import pathlib
import unittest

from scripts.compute_guest_profile_contract import load, validate
from scripts.windows_w1_native_plan import (
    FIXTURE_ID,
    MEDIA_SHA256,
    MEMORY_MIB,
    SYSTEM_DISK_BYTES,
    VCPUS,
    proxmox_plan,
    truenas_plan,
    WindowsW1PlanError,
)


class WindowsW1NativePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load(pathlib.Path("config/compute-guest-profiles.json"))
        validate(cls.profile)

    def test_portable_semantics_match_across_platforms(self):
        tn = truenas_plan(
            self.profile,
            pool="rdtepool",
            iso_path="/mnt/rdtepool/windows/windows11.iso",
            seed_path="/mnt/rdtepool/windows/adw1seed.iso",
            bridge="br0",
        )
        pve = proxmox_plan(
            self.profile,
            vmid=9301,
            storage="local-lvm",
            iso_volume="local:iso/windows11.iso",
            seed_volume="local:iso/adw1seed.iso",
            bridge="vmbr0",
        )
        self.assertEqual(tn["portable_intent"], pve["portable_intent"])
        req = tn["portable_intent"]["requirements"]
        self.assertEqual(req["virtual_processors"], VCPUS)
        self.assertEqual(req["memory_mib"], MEMORY_MIB)
        self.assertEqual(req["system_disk_gib"], 64)
        self.assertEqual(req["guest_readiness_oracle"], "serial-com1-exact-nonce")
        self.assertTrue(req["secure_boot"])
        self.assertEqual(req["tpm_version"], "2.0")
        self.assertEqual(tn["portable_intent"]["fixture"], FIXTURE_ID)
        self.assertEqual(tn["portable_intent"]["media"]["sha256"], MEDIA_SHA256)

    def test_truenas_lowering_preserves_windows_requirements(self):
        plan = truenas_plan(
            self.profile,
            pool="rdtepool",
            iso_path="/mnt/rdtepool/windows/windows11.iso",
            seed_path="/mnt/rdtepool/windows/adw1seed.iso",
            bridge="br0",
        )
        create = plan["vm_create"]
        self.assertEqual(create["vcpus"] * create["cores"] * create["threads"], 2)
        self.assertEqual(create["memory"], 4096)
        self.assertEqual(create["cpu_mode"], "HOST-PASSTHROUGH")
        self.assertEqual(create["bootloader"], "UEFI")
        self.assertEqual(create["bootloader_ovmf"], "OVMF_CODE_4M.secboot.fd")
        self.assertEqual(create["machine_type"], "pc-q35-6.2")
        self.assertTrue(create["trusted_platform_module"])
        self.assertTrue(create["enable_secure_boot"])
        self.assertTrue(create["hyperv_enlightenments"])
        disk = next(x for x in plan["device_templates"] if x["role"] == "system-disk")
        self.assertEqual(disk["attributes"]["type"], "AHCI")
        self.assertEqual(disk["attributes"]["zvol_volsize"], SYSTEM_DISK_BYTES)
        seed = next(x for x in plan["device_templates"] if x["role"] == "unattended-seed")
        self.assertEqual(seed["attributes"]["dtype"], "CDROM")
        self.assertEqual(seed["attributes"]["path"], "/mnt/rdtepool/windows/adw1seed.iso")
        self.assertEqual(plan["external_bindings"]["unattended_seed_contract"], "windows-w1-unattend-seed/v1")
        self.assertEqual(
            plan["post_install_transition"]["owned_roles"],
            ["install-media", "unattended-seed"],
        )
        nic = next(x for x in plan["device_templates"] if x["role"] == "network")
        self.assertEqual(nic["attributes"]["type"], "E1000")
        self.assertEqual(plan["guest_oracle"]["guest_device"], "COM1")
        self.assertEqual(plan["guest_oracle"]["transport"], "truenas-vm-console")
        self.assertIn("vm.get_console", plan["guest_oracle"]["surface"])
        self.assertEqual(plan["guest_oracle"]["seed_volume_label"], "ADW1SEED")
        self.assertFalse(plan["mutation_authorized"])

    def test_proxmox_lowering_preserves_windows_requirements(self):
        plan = proxmox_plan(
            self.profile,
            vmid=9301,
            storage="local-lvm",
            iso_volume="local:iso/windows11.iso",
            seed_volume="local:iso/adw1seed.iso",
            bridge="vmbr0",
        )
        create = plan["create_fields"]
        self.assertEqual(create["memory"], 4096)
        self.assertEqual(create["cores"] * create["sockets"], 2)
        self.assertEqual(create["cpu"], "host")
        self.assertEqual(create["bios"], "ovmf")
        self.assertEqual(create["machine"], "q35")
        self.assertEqual(create["ostype"], "win11")
        self.assertEqual(create["sata0"], "local-lvm:64")
        self.assertEqual(create["ide1"], "local:iso/adw1seed.iso,media=cdrom")
        self.assertEqual(create["ide2"], "local:iso/windows11.iso,media=cdrom")
        self.assertEqual(plan["external_bindings"]["unattended_seed_contract"], "windows-w1-unattend-seed/v1")
        ops = plan["post_install_transition"]["operations"]
        self.assertEqual([x["role"] for x in ops], [
            "detach-install-media",
            "detach-unattended-seed",
            "system-disk-only-boot",
        ])
        self.assertEqual(ops[0]["fields"]["delete"], "ide2")
        self.assertEqual(ops[1]["fields"]["delete"], "ide1")
        self.assertEqual(ops[2]["fields"]["boot"], "order=sata0")
        self.assertIn("pre-enrolled-keys=1", create["efidisk0"])
        self.assertIn("version=v2.0", create["tpmstate0"])
        self.assertEqual(create["net0"], "e1000,bridge=vmbr0")
        self.assertEqual(create["serial0"], "socket")
        self.assertEqual(create["boot"], "order=ide2;sata0")
        self.assertEqual(plan["guest_oracle"]["guest_device"], "COM1")
        self.assertEqual(plan["guest_oracle"]["transport"], "pve-termproxy")
        self.assertEqual(plan["guest_oracle"]["serial"], "serial0")
        self.assertIn("/termproxy", plan["guest_oracle"]["create_surface"])
        self.assertEqual(plan["source_binding"]["api2_qemu_blob"], "e029a204d121f3c8b104457ef14eb6d5ce029464")
        self.assertFalse(plan["mutation_authorized"])

    def test_external_binding_validation_fails_closed(self):
        with self.assertRaises(WindowsW1PlanError):
            truenas_plan(
                self.profile,
                pool="pool/dataset",
                iso_path="/mnt/pool/w.iso",
                seed_path="/mnt/pool/seed.iso",
                bridge="br0",
            )
        with self.assertRaises(WindowsW1PlanError):
            truenas_plan(
                self.profile,
                pool="rdtepool",
                iso_path="/mnt/rdtepool/windows/windows11.iso",
                seed_path="/mnt/rdtepool/windows/windows11.iso",
                bridge="br0",
            )
        with self.assertRaises(WindowsW1PlanError):
            proxmox_plan(
                self.profile,
                vmid=9301,
                storage="local-lvm",
                iso_volume="local:iso/windows11.iso",
                seed_volume="local:iso/windows11.iso",
                bridge="vmbr0",
            )
        with self.assertRaises(WindowsW1PlanError):
            proxmox_plan(
                self.profile,
                vmid=9301,
                storage="local-lvm",
                iso_volume="not-a-volume-id",
                seed_volume="local:iso/adw1seed.iso",
                bridge="vmbr0",
            )


if __name__ == "__main__":
    unittest.main()
