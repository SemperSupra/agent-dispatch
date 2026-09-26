import importlib.util
import pathlib
import tempfile
import unittest
import sys
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "android_edge_host_converge.py"
spec = importlib.util.spec_from_file_location("android_edge_host_converge", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

class ConvergerContractTests(unittest.TestCase):
    def test_contract_covers_three_audiences(self):
        c = mod.contract()
        self.assertEqual(set(c["audiences"]), {"human", "automation", "agent"})
        self.assertEqual(c["desired"]["host_os"], ["Windows", "Linux", "Darwin"])

    def test_empty_root_plans_install(self):
        with tempfile.TemporaryDirectory() as td:
            p = mod.plan(pathlib.Path(td))
            self.assertTrue(p.changed)
            self.assertEqual(p.action, "install-or-repair")

    def test_stage_ok_accepts_managed_windows_driver_payload_for_planning(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(mod.platform, "system", return_value="Windows"):
            root = pathlib.Path(td)
            driver = root / "usb_driver"
            driver.mkdir()
            (driver / "android_winusb.inf").write_text("fixture", encoding="utf-8")
            with mock.patch.object(mod, "_windows_driver_records", return_value=[]):
                p = mod.plan(root, "stage-ok")
            self.assertFalse(p.windows_usb_driver_package_needed)
            self.assertFalse(p.windows_driver_store_needed)

    def test_revert_empty_root_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            a = mod.revert(root)
            b = mod.revert(root)
            self.assertFalse(a["changed"])
            self.assertFalse(b["changed"])

    def test_unknown_os_is_rejected_for_install(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(mod.platform, "system", return_value="Plan9"):
            root = pathlib.Path(td) / "root"
            scratch = pathlib.Path(td) / "scratch"
            root.mkdir()
            scratch.mkdir()
            with self.assertRaises(RuntimeError):
                mod._install_platform_tools(root, scratch)

if __name__ == "__main__":
    unittest.main()
