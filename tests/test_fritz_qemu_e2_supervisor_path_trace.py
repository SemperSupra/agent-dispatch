import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_supervisor_path_trace.py"
spec = importlib.util.spec_from_file_location("fritz_e2_r4", SCRIPT)
r4 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r4)


class R4Tests(unittest.TestCase):
    def test_path_allowlist(self):
        self.assertTrue(r4.path_allowed("/lib/systemd/system/ctlmgr.service"))
        self.assertTrue(r4.path_allowed("/var/tmp/psupport.data"))
        self.assertFalse(r4.path_allowed("/home/runner/private"))

    def test_reduce_strace_order_and_outcome(self):
        raw = """100 openat(-100,"/lib/systemd/system/ctlmgr.service",0) = 3
100 access("/var/tmp/psupport.data",0) = -1 errno=2 (No such file or directory)
100 connect(3,{sun_path="/tmp/supervisor.ctrl.socket"},110) = -1 errno=2 (No such file or directory)
100 openat(-100,"/unlisted/secret",0) = 4
"""
        x = r4.reduce_strace(raw)
        self.assertTrue(x["targetUnitObserved"])
        self.assertTrue(x["psupportDataObserved"])
        self.assertTrue(x["controlSocketObserved"])
        self.assertEqual(x["records"][0]["outcome"], "success")
        self.assertEqual(x["records"][1]["outcome"], "ENOENT")
        self.assertEqual(len(x["records"]), 3)

    def test_classify_target_unit(self):
        x = {
            "targetUnitObserved": True,
            "psupportDataObserved": False,
            "avmipcdUnitObserved": False,
            "unitAccesses": [{"path": r4.TARGET_UNIT_PATH}],
        }
        self.assertEqual(r4.classify(x), "E2_TARGET_UNIT_OBSERVED")

    def test_classify_exit_before_unit_tree(self):
        x = {
            "targetUnitObserved": False,
            "psupportDataObserved": False,
            "avmipcdUnitObserved": False,
            "unitAccesses": [],
        }
        self.assertEqual(r4.classify(x), "E2_EXIT_BEFORE_UNIT_TREE_ACCESS")


if __name__ == "__main__":
    unittest.main()
