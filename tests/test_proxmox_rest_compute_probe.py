import pathlib
import unittest
from scripts.proxmox_rest_compute_probe import (
    PVE_CONTAINER_SOURCE, PVE_MANAGER_API_SOURCE, PVE_QEMU_PACKAGE_SOURCE, PVE_QEMU_SERVER_SOURCE,
    ProxmoxProbeError, lxc_create_fields, plan_only, vm_create_fields
)

class ProxmoxRestComputeContractTests(unittest.TestCase):
    def test_exact_container_source_is_bound(self):
        self.assertEqual(PVE_CONTAINER_SOURCE["commit"],"5eb5574ee9158ac40a5230de2cf18d7d6345709f")
        self.assertEqual(PVE_CONTAINER_SOURCE["package_version"],"6.1.10")
        self.assertEqual(PVE_QEMU_PACKAGE_SOURCE["commit"],"684796e835289dab11af8606fbf7358b93526dd6")
        self.assertEqual(PVE_MANAGER_API_SOURCE["commit"],"b9984c6d90a4bd80")
        self.assertEqual(PVE_QEMU_SERVER_SOURCE["commit"],"6785065b3f766f15f6f151af8ec27ec8bb5b07ab")
        self.assertEqual(PVE_QEMU_SERVER_SOURCE["package_version"],"9.1.15")
        self.assertEqual(PVE_QEMU_SERVER_SOURCE["api2_qemu_blob"],"e029a204d121f3c8b104457ef14eb6d5ce029464")
        self.assertEqual(PVE_MANAGER_API_SOURCE["apt_api_blob"],"9cb6e473436719f3024ac09fffaad8faf0d7160d")

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

    def test_vm_apply_source_gate_is_exact_package_bound(self):
        text=pathlib.Path("scripts/proxmox_rest_compute_probe.py").read_text(encoding="utf-8")
        self.assertIn('a.expected_qemu_server_version != PVE_QEMU_SERVER_SOURCE["package_version"]',text)
        self.assertIn('"qemu_server":PVE_QEMU_SERVER_SOURCE',text)

    def test_vm_payload_does_not_smuggle_media_or_key(self):
        f=vm_create_fields(9201)
        self.assertNotIn("ide2",f)
        self.assertNotIn("password",f)
        self.assertNotIn("ciuser",f)

    def test_apply_failure_path_has_owned_resource_cleanup(self):
        text=pathlib.Path("scripts/proxmox_rest_compute_probe.py").read_text(encoding="utf-8")
        self.assertIn("ownership_claimed=True",text)
        self.assertIn('failure_cleanup_stop',text)
        self.assertIn('failure_cleanup_delete',text)
        self.assertIn('{"purge":1}',text)
        self.assertIn('receipt["cleanup"]["absent"]',text)

if __name__=="__main__":
    unittest.main()
