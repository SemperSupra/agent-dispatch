import importlib.util
import unittest

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_svctl_start_ctlmgr.py"
spec = importlib.util.spec_from_file_location("fritz_r6", SCRIPT)
r6 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r6)


class R6Tests(unittest.TestCase):
    def test_status_changed_by_hash(self):
        a = {"exitCode":0,"stdoutBytes":4,"stdoutSha256":"a"}
        b = {"exitCode":0,"stdoutBytes":4,"stdoutSha256":"b"}
        self.assertTrue(r6.status_changed(a,b))

    def test_start_rejected(self):
        x = {
            "controlSocketReady": True,
            "start":{"exitCode":1},
            "ctlmgrTcpListeners":[],
            "ctlmgrProcessObserved":False,
            "httpAttempts":[],
        }
        self.assertEqual(r6.classify(x),"E2_R6_START_REJECTED")

    def test_start_accepted_status_changed(self):
        x = {
            "controlSocketReady": True,
            "start":{"exitCode":0},
            "statusChanged":True,
            "ctlmgrTcpListeners":[],
            "ctlmgrProcessObserved":False,
            "httpAttempts":[],
        }
        self.assertEqual(
            r6.classify(x),
            "E2_R6_START_ACCEPTED_STATUS_CHANGED_NO_PROCESS",
        )

    def test_process_beats_status(self):
        x = {
            "controlSocketReady": True,
            "start":{"exitCode":0},
            "statusChanged":False,
            "ctlmgrTcpListeners":[],
            "ctlmgrProcessObserved":True,
            "httpAttempts":[],
        }
        self.assertEqual(r6.classify(x),"E2_R6_CTLMGR_PROCESS_OBSERVED")

    def test_login_beats_all(self):
        x = {
            "controlSocketReady": True,
            "start":{"exitCode":0},
            "statusChanged":False,
            "ctlmgrTcpListeners":[80],
            "ctlmgrProcessObserved":True,
            "httpAttempts":[{"httpStatus":200,"responseMarkers":["session_info"]}],
        }
        self.assertEqual(r6.classify(x),"E2_LOGIN_HTTP_SUPPORTED")


if __name__ == "__main__":
    unittest.main()
