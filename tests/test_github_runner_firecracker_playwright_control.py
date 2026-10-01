import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "github_runner_firecracker_playwright_control.py"
JS = ROOT / "experiments" / "firecracker" / "guest" / "playwright-control.js"
INIT = ROOT / "experiments" / "firecracker" / "guest" / "playwright-control-init-x86_64.c"

SPEC = importlib.util.spec_from_file_location("pw", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerPlaywrightControlTests(unittest.TestCase):
    def test_authority_and_pinned_playwright_version(self):
        self.assertEqual(MOD.AUTHORITY, "SemperSupra/agent-dispatch-private#415")
        self.assertEqual(MOD.PLAYWRIGHT_VERSION, "1.63.0")
        self.assertEqual(
            MOD.BASE_IMAGE_TAG,
            "mcr.microsoft.com/playwright:v1.63.0-noble",
        )

    def test_guest_control_is_networkless_and_requests_browser_sandbox(self):
        source = JS.read_text()
        self.assertIn("chromiumSandbox: true", source)
        self.assertIn("network_used: false", source)
        self.assertIn("file:///tmp/playwright-control.html", source)
        self.assertNotIn("http://", source)
        self.assertNotIn("https://", source)
        self.assertNotIn("--no-sandbox", source)

    def test_bridge_drops_to_unprivileged_guest_user(self):
        source = INIT.read_text()
        self.assertIn("SYS_setgid,20001", source)
        self.assertIn("SYS_setuid,20001", source)
        self.assertIn("/usr/bin/node", source)

    def test_jail_config_uses_chroot_visible_boot_paths_and_no_network(self):
        source = SCRIPT.read_text()
        self.assertIn('cfg["boot-source"]["kernel_image_path"] = "/vmlinux"', source)
        self.assertIn('cfg["boot-source"]["initrd_path"] = "/initrd.cpio"', source)
        self.assertIn('cfg["network-interfaces"] = []', source)
        self.assertIn('"network_interfaces": 0', source)

    def test_public_gha_visibility_is_fail_closed(self):
        source = SCRIPT.read_text()
        self.assertIn('venue="public-gha"', source)
        self.assertIn('visibility="public_safe"', source)
        self.assertNotIn('visibility="private"', source)

    def test_setup_and_cleanup_failures_keep_typed_classification(self):
        source = SCRIPT.read_text()
        self.assertIn("class ProbeError(RuntimeError):", source)
        self.assertIn('ProbeError("VENUE_LIMITATION"', source)
        self.assertIn('ProbeError("SETUP_REQUIRED"', source)
        self.assertIn("exec_adapter.select_kvm_access()", source)
        self.assertIn("callable KVM is required for P0a", source)
        self.assertIn('"CLEANUP_FAILURE"', source)
        self.assertIn("rootfs staging cleanup failed", source)
        self.assertIn('receipt["kvm_access"]', source)
        self.assertIn('receipt["runner"]', source)

    def test_externalization_and_cleanup_can_overrule_guest_success(self):
        source = SCRIPT.read_text()
        self.assertIn('"ORACLE_FAILURE"', source)
        self.assertIn('"CLEANUP_FAILURE"', source)
        self.assertIn('"host_output_validation": outputs_valid', source)
        self.assertIn('"cleanup_ok": cleanup["ok"]', source)

    def test_host_validator_is_separate_from_guest_marker(self):
        source = SCRIPT.read_text()
        self.assertIn("host/playwright-control-v1", source)
        self.assertIn("_inspect_outputs", source)
        self.assertIn("debugfs", source)
        self.assertIn('"accepted": False', source)
        self.assertIn('"candidate_valid": outputs_valid', source)
        self.assertIn("private reconciliation remains required", source)

    def test_rootfs_export_does_not_duplicate_full_tar(self):
        source = SCRIPT.read_text()
        self.assertIn("playwright_rootfs_export_extract", source)
        self.assertIn('docker export "$1" | sudo -n tar', source)
        self.assertNotIn('root_tar = work / "rootfs.tar"', source)
        self.assertNotIn('"docker", "export", "-o"', source)


if __name__ == "__main__":
    unittest.main()
