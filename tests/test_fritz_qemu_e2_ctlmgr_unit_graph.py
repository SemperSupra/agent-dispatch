import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_ctlmgr_unit_graph.py"
spec = importlib.util.spec_from_file_location("unitgraph", SCRIPT)
m = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(m)


class UnitGraphTests(unittest.TestCase):
    def test_dependency_filter(self):
        self.assertEqual(
            m.dependency_units("network.target weird-token ctlmgr.service"),
            ["ctlmgr.service", "network.target"],
        )

    def test_exec_shape_keeps_path_and_hides_arbitrary(self):
        got = m.safe_exec_shape('/usr/bin/ctlmgr --mode secret-value')
        self.assertEqual(got["executable"], "/usr/bin/ctlmgr")
        self.assertEqual(got["args"][0], {"kind":"option","value":"--mode"})
        self.assertEqual(got["args"][1]["kind"], "opaque")
        self.assertNotIn("secret-value", str(got))

    def test_ctlmgr_unit_reduction(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            p = root / "lib" / "systemd" / "system"
            p.mkdir(parents=True)
            (p / "ctlmgr.service").write_text(
                "[Unit]\nAfter=network.target\n"
                "[Service]\nType=simple\nExecStart=/usr/bin/ctlmgr\n"
                "[Install]\nWantedBy=multi-user.target\n",
                encoding="utf-8",
            )
            got = m.reduce_ctlmgr_unit(root)
            self.assertTrue(got["present"])
            self.assertEqual(got["serviceType"], "simple")
            self.assertEqual(got["exec"][0]["executable"], "/usr/bin/ctlmgr")
            self.assertIn(
                {"section":"Install","key":"WantedBy","unit":"multi-user.target"},
                got["dependencies"],
            )

    def test_candidate_target_from_wantedby(self):
        ctlmgr = {
            "dependencies":[
                {"section":"Install","key":"WantedBy","unit":"multi-user.target"}
            ]
        }
        got = m.candidate_supervisor_targets(ctlmgr, [])
        self.assertEqual(
            got,
            [{"target":"multi-user.target","evidence":"ctlmgr.service:WantedBy"}],
        )


if __name__ == "__main__":
    unittest.main()
