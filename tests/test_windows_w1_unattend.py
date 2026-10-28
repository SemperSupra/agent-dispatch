import json
import pathlib
import tempfile
import unittest
import xml.etree.ElementTree as ET

from scripts.windows_w1_unattend import (
    MARKER_PREFIX,
    SEED_LABEL,
    UNATTEND_NS,
    WindowsW1SeedError,
    bootstrap_script,
    build_unattend,
    write_seed,
)


class WindowsW1UnattendTests(unittest.TestCase):
    def test_unattend_is_uefi_disk_zero_and_has_no_secret_material(self):
        xml = build_unattend("Windows 11 Enterprise Evaluation")
        root = ET.fromstring(xml)
        ns = {"u": UNATTEND_NS}
        self.assertEqual(root.tag, f"{{{UNATTEND_NS}}}unattend")
        self.assertIn("<Type>EFI</Type>", xml)
        self.assertIn("<Type>MSR</Type>", xml)
        self.assertIn("<PartitionID>3</PartitionID>", xml)
        self.assertIn("/IMAGE/NAME", xml)
        self.assertIn("Windows 11 Enterprise Evaluation", xml)
        self.assertIn(SEED_LABEL, xml)
        self.assertNotIn("ProductKey", xml)
        self.assertNotIn("Password", xml)
        paths = root.findall(".//u:RunSynchronousCommand/u:Path", ns)
        self.assertEqual(len(paths), 1)
        self.assertLessEqual(len(paths[0].text or ""), 259)

    def test_bootstrap_emits_exact_nonce_and_registers_restart_oracle(self):
        nonce = "windowsw1nonce20261006"
        ps1 = bootstrap_script(nonce)
        self.assertIn(MARKER_PREFIX + nonce, ps1)
        self.assertIn("SerialPort", ps1)
        self.assertIn("'COM1'", ps1)
        self.assertIn("115200", ps1)
        self.assertIn("New-ScheduledTaskTrigger -AtStartup", ps1)
        self.assertIn("Register-ScheduledTask", ps1)
        self.assertNotIn("password", ps1.lower())
        self.assertNotIn("productkey", ps1.lower())

    def test_seed_contract_is_deterministic_and_has_no_network_or_guest_agent_dependency(self):
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            r1 = write_seed(pathlib.Path(td1), "windowsw1nonce20261006", "Windows 11 Enterprise Evaluation")
            r2 = write_seed(pathlib.Path(td2), "windowsw1nonce20261006", "Windows 11 Enterprise Evaluation")
            self.assertEqual(r1, r2)
            self.assertEqual(r1["seed_volume_label"], SEED_LABEL)
            self.assertFalse(r1["security"]["network_dependency"])
            self.assertFalse(r1["security"]["guest_agent_dependency"])
            self.assertFalse(r1["security"]["embedded_product_key"])
            self.assertFalse(r1["security"]["embedded_password"])
            for name in ("Autounattend.xml", "w1-bootstrap.ps1", "seed-contract.json"):
                self.assertTrue((pathlib.Path(td1) / name).is_file())
            loaded = json.loads((pathlib.Path(td1) / "seed-contract.json").read_text())
            self.assertEqual(loaded["nonce_marker"], MARKER_PREFIX + "windowsw1nonce20261006")

    def test_invalid_bindings_fail_closed(self):
        with self.assertRaises(WindowsW1SeedError):
            build_unattend("bad\nimage")
        with self.assertRaises(WindowsW1SeedError):
            bootstrap_script("short")


if __name__ == "__main__":
    unittest.main()
