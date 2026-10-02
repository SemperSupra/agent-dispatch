import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_svctl_status_runtime.py"
spec = importlib.util.spec_from_file_location("fritz_e2_r3", SCRIPT)
r3 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r3)


class SvctlStatusRuntimeTests(unittest.TestCase):
    def test_classification_login(self):
        x = {"httpAttempts":[{"httpStatus":200,"responseMarkers":["session_info"]}]}
        self.assertEqual(r3.classify(x), "E2_LOGIN_HTTP_SUPPORTED")

    def test_classification_ctlmgr_after_status(self):
        x = {"httpAttempts":[],"ctlmgrProcessObservedAfterStatus":True}
        self.assertEqual(r3.classify(x), "E2_CTLMGR_OBSERVED_AFTER_STATUS")

    def test_classification_supervisor_not_live(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":False,
        }
        self.assertEqual(r3.classify(x), "E2_SUPERVISOR_NOT_LIVE")

    def test_classification_status_completed(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":True,
            "svctlStatusAttempted":True,"svctlStatusExitCode":0,
        }
        self.assertEqual(r3.classify(x), "E2_SVCTL_STATUS_COMPLETED")

    def test_classification_control_socket_absent(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":True,
            "svctlStatusAttempted":True,"svctlStatusExitCode":1,
            "controlSocketBeforeStatus":{"exists":False,"type":"missing"},
            "controlSocketAfterStatus":{"exists":False,"type":"missing"},
        }
        self.assertEqual(r3.classify(x), "E2_SUPERVISOR_CONTROL_SOCKET_ABSENT")

    def test_classification_status_rejected(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":True,
            "svctlStatusAttempted":True,"svctlStatusExitCode":1,
            "controlSocketBeforeStatus":{"exists":True,"type":"socket"},
            "controlSocketAfterStatus":{"exists":True,"type":"socket"},
        }
        self.assertEqual(r3.classify(x), "E2_SVCTL_STATUS_REJECTED")


if __name__ == "__main__":
    unittest.main()
