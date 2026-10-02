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

    def test_classification_ctlmgr_observed(self):
        x = {"httpAttempts":[],"ctlmgrProcessObserved":True}
        self.assertEqual(r3.classify(x), "E2_CTLMGR_OBSERVED")

    def test_classification_status_completed(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObserved":False,
            "svctlStatusAttempted":True,"svctlStatusExitCode":0,
        }
        self.assertEqual(r3.classify(x), "E2_SVCTL_STATUS_COMPLETED")

    def test_classification_status_no_control_socket(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObserved":False,
            "svctlStatusAttempted":True,"svctlStatusExitCode":1,
            "controlSocketObserved":False,
        }
        self.assertEqual(r3.classify(x), "E2_SVCTL_STATUS_NO_CONTROL_SOCKET")

    def test_classification_status_rejected_with_socket(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObserved":False,
            "svctlStatusAttempted":True,"svctlStatusExitCode":1,
            "controlSocketObserved":True,
        }
        self.assertEqual(r3.classify(x), "E2_SVCTL_STATUS_REJECTED")

    def test_classification_transient_supervisor_no_socket(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObserved":False,
            "svctlStatusAttempted":False,
            "supervisorProcessObserved":True,
            "controlSocketObserved":False,
        }
        self.assertEqual(r3.classify(x), "E2_SUPERVISOR_TRANSIENT_NO_CONTROL_SOCKET")

    def test_classification_never_observed(self):
        x = {
            "httpAttempts":[],"ctlmgrProcessObserved":False,
            "svctlStatusAttempted":False,
            "supervisorProcessObserved":False,
            "controlSocketObserved":False,
        }
        self.assertEqual(r3.classify(x), "E2_SUPERVISOR_NEVER_OBSERVED")


if __name__ == "__main__":
    unittest.main()
