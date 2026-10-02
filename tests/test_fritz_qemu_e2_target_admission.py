import importlib.util
import os
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_target_admission.py"
spec = importlib.util.spec_from_file_location("fritz_e2_d5", SCRIPT)
d5 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(d5)


class TargetAdmissionTests(unittest.TestCase):
    def test_parse_unit_only_safe_unit_names(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "x.service"
            p.write_text(
                "[Unit]\nAfter=a.service /bad/path $(bad) b.target\n"
                "[Install]\nWantedBy=network.target\n",
                encoding="utf-8",
            )
            meta = d5.parse_unit(p)
            self.assertEqual(meta["After"], ["a.service", "b.target"])
            self.assertEqual(meta["WantedBy"], ["network.target"])

    def test_recover_prefers_smaller_exact_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            u = root / "lib/systemd/system"
            u.mkdir(parents=True)
            (u / "network.target").write_text("[Unit]\n", encoding="utf-8")
            (u / "prodtest-network.target").write_text("[Unit]\n", encoding="utf-8")
            (u / "ctlmgr.service").write_text(
                "[Install]\nWantedBy=network.target prodtest-network.target\n",
                encoding="utf-8",
            )
            (u / "extra.service").write_text(
                "[Install]\nWantedBy=network.target\n",
                encoding="utf-8",
            )
            g = d5.recover(root)
            self.assertTrue(g["targets"]["network.target"]["ctlmgrAdmitted"])
            self.assertTrue(g["targets"]["prodtest-network.target"]["ctlmgrAdmitted"])
            self.assertEqual(g["mechanicalNarrowestCtlmgrTarget"], "prodtest-network.target")

    def test_symlink_membership(self):
        with tempfile.TemporaryDirectory() as td:
            u = pathlib.Path(td)
            d = u / "network.target.wants"
            d.mkdir()
            os.symlink("../ctlmgr.service", d / "ctlmgr.service")
            links = d5.symlink_memberships(u, "network.target")
            self.assertEqual(links["wants"], ["ctlmgr.service"])


if __name__ == "__main__":
    unittest.main()
