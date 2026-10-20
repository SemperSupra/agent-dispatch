"""Public-safe adversarial bindings tests for native W1 plan construction only.

No TrueNAS/Proxmox API connections, VM creation, media upload, credentials,
Windows Setup, product deployment, or mutation admission.
"""
import pathlib
import unittest

from scripts.compute_guest_profile_contract import load
from scripts.windows_w1_native_plan import (
    WindowsW1PlanError, truenas_plan, proxmox_plan
)
PROFILE=pathlib.Path("config/compute-guest-profiles.json")
class SafeNativeMediaBindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile=load(PROFILE)

    def tn(self,**kwargs):
        args=dict(pool="rdtepool",
                  iso_path="/mnt/rdtepool/windows/windows11.iso",
                  seed_path="/mnt/rdtepool/windows/adw1seed.iso",
                  bridge="br0")
        args.update(kwargs)
        return truenas_plan(self.profile,**args)

    def pve(self,**kwargs):
        args=dict(vmid=9301,storage="local-lvm",
                  iso_volume="local:iso/windows11.iso",
                  seed_volume="local:iso/adw1seed.iso",
                  bridge="vmbr0")
        args.update(kwargs)
        return proxmox_plan(self.profile,**args)

    def test_typical_native_plans_remain_inert(self):
        for plan in (self.tn(),self.pve()):
            self.assertFalse(plan["mutation_authorized"])
            self.assertEqual(plan["schema"],"windows-w1-native-plan/v1")

    def test_true_nas_traversal_and_noniso_media_denied(self):
        bad=(
            "/mnt/rdtepool/../private/windows11.iso",
            "/mnt/rdtepool/./windows11.iso",
            "/mnt//rdtepool/windows.iso",
            "/mnt/rdtepool/windows/../../etc/windows.iso",
            "/mnt/rdtepool/windows/secrets.txt",
            "/etc/windows11.iso",
            "/mnt/rdtepool/windows/evil\nname.iso",
            "/mnt/rdtepool/windows/sneaky.iso,readonly=false",
            "/mnt/rdtepool/windows\\evil.iso",
        )
        for x in bad:
            for key in ("iso_path","seed_path"):
                with self.subTest(key=key,x=x),self.assertRaises(WindowsW1PlanError):
                    self.tn(**{key:x})

    def test_pve_device_field_injection_and_wrong_volumes_denied(self):
        bad=(
            "local:iso/windows11.iso,media=disk",
            "local:iso/../private/windows11.iso",
            "local:iso/windows11.iso;something",
            "local:iso/evil\ncdrom.iso",
            "local-lvm:root/images/1.raw",
            ":iso/blank.iso",
            "local:iso/.iso",
            "local:iso/dir//image.iso",
            "local:iso/windows11.img",
            "local",
        )
        for x in bad:
            for key in ("iso_volume","seed_volume"):
                with self.subTest(key=key,x=x),self.assertRaises(WindowsW1PlanError):
                    self.pve(**{key:x})

    def test_pve_network_bridge_parameter_injection_denied(self):
        for x in ("vmbr0,firewall=0","vmbr0;agent=1","vmbr0/../vmbr1",
                  ".","..","vmbr0 tab","vmbr0\x1b"):
            with self.subTest(x=x),self.assertRaises(WindowsW1PlanError):
                self.pve(bridge=x)

    def test_native_iso_distinctness_preserved(self):
        with self.assertRaises(WindowsW1PlanError):
            self.pve(iso_volume="local:iso/same.iso",seed_volume="local:iso/same.iso")
        with self.assertRaises(WindowsW1PlanError):
            self.tn(iso_path="/mnt/rdtepool/windows/same.iso",
                    seed_path="/mnt/rdtepool/windows/same.iso")

if __name__=="__main__":unittest.main()
