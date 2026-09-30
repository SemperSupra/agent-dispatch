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

    def test_host_validator_is_separate_from_guest_marker(self):
        source = SCRIPT.read_text()
        self.assertIn("host/playwright-control-v1", source)
        self.assertIn("_inspect_outputs", source)
        self.assertIn("debugfs", source)


if __name__ == "__main__":
    unittest.main()
