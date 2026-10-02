import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_predecessor_chain.py"
spec = importlib.util.spec_from_file_location("fritz_r7", SCRIPT)
r7 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r7)


class R7Tests(unittest.TestCase):
    def test_status_exit_zero_alone_not_progress(self):
        pre = {"exitCode":0,"stdoutBytes":10,"stdoutSha256":"a"}
        post = {"exitCode":0,"stdoutBytes":10,"stdoutSha256":"a"}
        self.assertFalse(r7.stage_progressed(pre, post, 0, 0))

    def test_status_change_is_progress(self):
        pre = {"exitCode":0,"stdoutBytes":10,"stdoutSha256":"a"}
        post = {"exitCode":0,"stdoutBytes":11,"stdoutSha256":"b"}
        self.assertTrue(r7.stage_progressed(pre, post, 0, 0))

    def test_execve_is_progress(self):
        pre = {"exitCode":0,"stdoutBytes":10,"stdoutSha256":"a"}
        post = dict(pre)
        self.assertTrue(r7.stage_progressed(pre, post, 0, 1))

    def test_net_basic_stop_class(self):
        x = {
            "controlSocketReady":True,
            "stages":[{"service":"net_basic","progressed":False}],
        }
        self.assertEqual(r7.classify(x),"E2_R7_NET_BASIC_NO_TRANSITION")

    def test_avmipcd_stop_class(self):
        x = {
            "controlSocketReady":True,
            "stages":[
                {"service":"net_basic","progressed":True},
                {"service":"avmipcd","progressed":False},
            ],
        }
        self.assertEqual(r7.classify(x),"E2_R7_AVMIPCD_NO_TRANSITION")


if __name__ == "__main__":
    unittest.main()
