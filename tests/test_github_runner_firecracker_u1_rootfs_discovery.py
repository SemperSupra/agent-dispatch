import importlib.util, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("u1d",ROOT/"scripts"/"github_runner_firecracker_u1_rootfs_discovery.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class U1DiscoveryTests(unittest.TestCase):
    def test_version_key(self):
        self.assertEqual(MOD._version_key("x86_64/ubuntu-24.04.squashfs"),(24,4))
        self.assertEqual(MOD._version_key("x86_64/ubuntu-24.10.1.squashfs"),(24,10,1))
    def test_manifest_is_pinned_prefix(self):
        import json
        m=json.loads(MOD.KERNEL_MANIFEST.read_text())
        self.assertRegex(m["firecracker_ci_prefix"],r"^firecracker-ci/[0-9]{8}-[^/]+-0/$")
if __name__=="__main__": unittest.main()
