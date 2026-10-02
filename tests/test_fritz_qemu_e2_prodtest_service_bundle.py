import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_prodtest_service_bundle.py"
SPEC = importlib.util.spec_from_file_location("d6", SCRIPT)
d6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d6)


class BundleTests(unittest.TestCase):
    def write(self, root, name, text):
        p = pathlib.Path(root) / "lib/systemd/system" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def fixture(self):
        td = tempfile.TemporaryDirectory()
        root = pathlib.Path(td.name)
        self.write(root, "ctlmgr.service", """[Unit]
After=avmipcd.service
[Service]
Type=notify
EnvironmentFile=/var/tmp/psupport.data
ExecStart=/usr/bin/ctlmgr
ConditionPathExists=/etc/example
[Install]
WantedBy=prodtest-network.target
""")
        self.write(root, "avmipcd.service", """[Service]
Type=simple
ExecStart=/usr/bin/avmipcd --foreground
[Install]
WantedBy=prodtest-network.target
""")
        self.write(root, "dsld.service", "[Service]\nExecStart=/usr/bin/dsld\n")
        self.write(root, "multid.service", "[Service]\nExecStart=/usr/bin/multid\n")
        self.write(root, "net_basic.service", "[Service]\nExecStart=/usr/bin/net_basic foo\n")
        self.write(root, "network-pre.target", "[Unit]\nBefore=ctlmgr.service\n")
        return td, root

    def test_recover_bundle_and_graph(self):
        td, root = self.fixture()
        try:
            b = d6.recover(root)
            self.assertEqual(b["missingUnits"], [])
            ctl = b["units"]["ctlmgr.service"]
            self.assertEqual(ctl["serviceType"], "notify")
            self.assertEqual(ctl["exec"][0]["executable"], "/usr/bin/ctlmgr")
            self.assertEqual(ctl["paths"][0]["path"], "/var/tmp/psupport.data")
            self.assertEqual(ctl["conditions"][0]["operand"]["value"], "/etc/example")
            self.assertEqual(b["graph"]["ctlmgr"]["orderingPredecessors"], ["avmipcd.service"])
            self.assertEqual(b["graph"]["ctlmgr"]["hardRequirements"], [])
            self.assertIn("/usr/bin/avmipcd", b["graph"]["nextRuntimeExecWatchlist"])
            self.assertIn("/usr/bin/ctlmgr", b["graph"]["nextRuntimeExecWatchlist"])
        finally:
            td.cleanup()

    def test_opaque_arguments_are_hashed(self):
        shape = d6.safe_exec("/bin/example secret=value --ok /tmp/a")
        self.assertEqual(shape["executable"], "/bin/example")
        self.assertEqual(shape["args"][0]["kind"], "opaque")
        self.assertEqual(shape["args"][1], {"kind":"option","value":"--ok"})
        self.assertEqual(shape["args"][2], {"kind":"absolute-path","value":"/tmp/a"})

    def test_after_not_promoted_to_hard_requirement(self):
        td, root = self.fixture()
        try:
            g = d6.recover(root)["graph"]["ctlmgr"]
            self.assertEqual(g["hardRequirements"], [])
            self.assertEqual(g["orderingPredecessors"], ["avmipcd.service"])
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
