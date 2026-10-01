import unittest
from scripts.proxmox_rest_compute_probe import (
    ProxmoxProbeError, lxc_create_fields, plan_only, vm_create_fields
)

class ProxmoxRestComputeContractTests(unittest.TestCase):
    def test_lxc_plan_uses_rest_and_unprivileged_container(self):
        p=plan_only("container",9101,"local:vztmpl/debian.tar.zst")
        self.assertEqual(p["create_path"],"/nodes/{node}/lxc")
        self.assertEqual(p["create_fields"]["unprivileged"],1)
        self.assertEqual(p["create_fields"]["start"],0)
        self.assertNotIn("pct",str(p))

    def test_vm_plan_uses_rest_and_native_vm_shape(self):
        p=plan_only("vm",9201,None)
        self.assertEqual(p["create_path"],"/nodes/{node}/qemu")
        self.assertEqual(p["create_fields"]["bios"],"ovmf")
        self.assertEqual(p["create_fields"]["machine"],"q35")
        self.assertEqual(p["create_fields"]["cpu"],"host")
        self.assertNotIn("qm ",str(p))

    def test_container_requires_exact_template_identity(self):
        with self.assertRaises(ProxmoxProbeError):
            plan_only("container",9101,None)

    def test_vm_payload_does_not_smuggle_media_or_key(self):
        f=vm_create_fields(9201)
        self.assertNotIn("ide2",f)
        self.assertNotIn("password",f)
        self.assertNotIn("ciuser",f)

if __name__=="__main__":
    unittest.main()
