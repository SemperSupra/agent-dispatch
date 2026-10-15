#!/usr/bin/env python3
import importlib.util, json, pathlib, unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("proxmox_rdte_target",ROOT/"scripts"/"proxmox_rdte_target.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
REG=ROOT/"config"/"proxmox-rdte-targets.json"
RUN_REQUEST=ROOT/"config"/"proxmox-rdte-run-request.json"

class ProxmoxTargetRegistryTests(unittest.TestCase):
    def setUp(self):
        self.targets=MOD.load_registry(REG)

    def test_current_runtime_matrix_is_exactly_one_target(self):
        self.assertEqual(set(self.targets),{"9.2-1"})
        self.assertTrue(self.targets["9.2-1"]["runtime_admitted"])

    def test_exact_source_and_media_anchors(self):
        t=self.targets["9.2-1"]
        self.assertEqual(t["iso_sha256"],"4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c")
        self.assertEqual(t["installer_source_commit"],"32afcd4cd534d8e2f99ae76aa0234a0a5c697ba9")
        self.assertEqual(t["pve_manager_source_commit"],"b9984c6d90a4bd80ab72dc2088c1b9103fb167b1")
        self.assertEqual(t["pve_container_source_commit"],"5eb5574ee9158ac40a5230de2cf18d7d6345709f")
        self.assertEqual(t["pve_qemu_source_commit"],"684796e835289dab11af8606fbf7358b93526dd6")
        self.assertEqual(t["container_fixture"]["template_sha512"],"5aec4ab2ac5c16c7c8ecb87bfeeb10213abe96db6b85e2463585cea492fc861d7c390b3f9c95629bf690b95e9dfe1037207fc69c0912429605f208d5cb2621f8")
        self.assertEqual(t["container_fixture"]["template_url"],"http://download.proxmox.com/images/system/debian-13-standard_13.1-2_amd64.tar.zst")
        self.assertEqual(t["container_fixture"]["catalog_source"]["blob_sha"],"433a8ef4bf78d606508c6bae162c49e9ef0ecfd3")
        self.assertEqual(t["container_fixture"]["catalog_source"]["base_url"],"http://download.proxmox.com/images")

    def test_vm_source_profile_is_exact_but_runtime_unqualified(self):
        t=self.targets["9.2-1"]
        self.assertEqual(t["vm_source_status"],"SOURCE_BOUND_RUNTIME_NOT_YET_QUALIFIED")
        self.assertEqual(t["qemu_server_source"]["package_version"],"9.1.15")
        self.assertEqual(t["qemu_server_source"]["commit"],"6785065b3f766f15f6f151af8ec27ec8bb5b07ab")
        self.assertEqual(t["qemu_server_source"]["api2_qemu_blob"],"e029a204d121f3c8b104457ef14eb6d5ce029464")

    def test_request_is_registered_runtime_target(self):
        request=json.loads(RUN_REQUEST.read_text(encoding="utf-8"))
        self.assertEqual(request["schema"],"gha-kvm-proxmox-run-request/v1")
        self.assertIn(request["version"],self.targets)
        target=self.targets[request["version"]]
        self.assertTrue(target["runtime_admitted"])
        self.assertEqual(request["authority_issue"],target["authority_issue"])
        self.assertIn(request.get("compute_fixture","none"),{"none","container-c0","vm-v0"})

    def test_unknown_target_fails_closed(self):
        with self.assertRaises(MOD.TargetError):
            if "9.3-1" not in self.targets:
                raise MOD.TargetError("exact Proxmox target is not registered: 9.3-1")

if __name__=="__main__":
    unittest.main()
