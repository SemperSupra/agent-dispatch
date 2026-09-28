import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PVE = ROOT / "scripts" / "gha_kvm_proxmox_rdte.sh"
TRUENAS = ROOT / "scripts" / "gha_kvm_truenas_rdte.sh"
TRUENAS_RPC = ROOT / "scripts" / "truenas_installer_rpc_probe.py"


class SystemRdteContractTests(unittest.TestCase):
    def test_shell_syntax(self):
        for path in (PVE, TRUENAS):
            cp = subprocess.run(["bash", "-n", str(path)], text=True, capture_output=True)
            self.assertEqual(cp.returncode, 0, f"{path}: {cp.stderr}")

    def test_common_evidence_contract(self):
        for path in (PVE, TRUENAS):
            text = path.read_text(encoding="utf-8")
            self.assertIn("gha-kvm-system-lab/v1", text)
            self.assertIn("oracleSatisfied", text)
            self.assertIn("classification", text)
            self.assertIn("passwordless sudo KVM boundary", text)
            self.assertIn("SKIPPED_GUARDRAIL", text)
            self.assertIn('rm -rf -- "$STATE_DIR"', text)

    def test_no_private_runner_or_secret_surface(self):
        forbidden = [
            "self-hosted",
            "garm-provider-truenas-private",
            "agent-dispatch-private.git",
            "ghp_",
            "github_pat_",
            "ACTIONS_RUNNER_INPUT_TOKEN",
        ]
        for path in (PVE, TRUENAS):
            text = path.read_text(encoding="utf-8")
            for needle in forbidden:
                self.assertNotIn(needle, text)

    def test_proxmox_is_pinned_and_uses_vendor_auto_install_contract(self):
        text = PVE.read_text(encoding="utf-8")
        self.assertIn("proxmox-ve_9.2-1.iso", text)
        self.assertIn(
            "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
            text,
        )
        self.assertIn('mode = "iso"', text)
        self.assertIn('source = "from-dhcp"', text)
        self.assertIn('filesystem = "ext4"', text)
        self.assertIn('disk-list = ["sda"]', text)
        self.assertIn("/api2/json/version", text)
        self.assertNotIn("xdotool", text)

    def test_truenas_is_pinned_and_digest_sidecar_is_required(self):
        text = TRUENAS.read_text(encoding="utf-8")
        self.assertIn("TrueNAS-26.0.0-BETA.3.iso", text)
        self.assertIn("TrueNAS-26.0.0-BETA.3.iso.sha256", text)
        self.assertIn("RAM_MIB=8192", text)
        self.assertIn("installer-boot", text)
        self.assertIn("installer-rpc", text)
        self.assertIn("truenas_installer_rpc_probe.py", text)
        self.assertNotIn("nightly", text.lower())
        self.assertNotIn("xdotool", text)

    def test_no_literal_escaped_shell_parameter_expansions(self):
        needle = chr(92) + "$" + "{"
        for path in (PVE, TRUENAS):
            self.assertNotIn(needle, path.read_text(encoding="utf-8"))


    def test_truenas_rpc_probe_is_dependency_free_and_read_only(self):
        text = TRUENAS_RPC.read_text(encoding="utf-8")
        for method in ("is_adopted", "system_info", "list_disks", "list_network_interfaces"):
            self.assertIn(method, text)
        self.assertNotIn('"install"', text)
        self.assertNotIn("pip install", text)
        cp = subprocess.run(
            ["python3", "-m", "py_compile", str(TRUENAS_RPC)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)


if __name__ == "__main__":
    unittest.main()
