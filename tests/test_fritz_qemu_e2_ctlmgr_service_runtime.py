import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_ctlmgr_service_runtime.py"
spec = importlib.util.spec_from_file_location("fritz_e2_r2", SCRIPT)
r2 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r2)


class CtlmgrServiceRuntimeTests(unittest.TestCase):
    def test_classification_login(self):
        x = {"httpAttempts":[{"httpStatus":200,"responseMarkers":["session_info"]}]}
        self.assertEqual(r2.classify(x), "E2_LOGIN_HTTP_SUPPORTED")

    def test_classification_listener(self):
        x = {"httpAttempts":[],"ctlmgrTcpListeners":[80],"ctlmgrProcessObserved":True}
        self.assertEqual(r2.classify(x), "E2_CTLMGR_LISTENER_OBSERVED")

    def test_classification_ctlmgr_started(self):
        x = {"httpAttempts":[],"ctlmgrTcpListeners":[],"ctlmgrProcessObserved":True}
        self.assertEqual(r2.classify(x), "E2_CTLMGR_STARTED_NO_LISTENER")

    def test_classification_supervisor_only(self):
        x = {
            "httpAttempts":[],"ctlmgrTcpListeners":[],
            "ctlmgrProcessObserved":False,"supervisorProcessObserved":True,
        }
        self.assertEqual(r2.classify(x), "E2_SUPERVISOR_RUNNING_CTLMGR_NOT_OBSERVED")

    def test_classification_target_rejected(self):
        x = {
            "httpAttempts":[],"ctlmgrTcpListeners":[],
            "ctlmgrProcessObserved":False,"supervisorProcessObserved":False,
            "supervisorLauncherExitCode":1,
        }
        self.assertEqual(r2.classify(x), "E2_SERVICE_TARGET_REJECTED_OR_DEPENDENCY")

    def test_classification_clean_exit(self):
        x = {
            "httpAttempts":[],"ctlmgrTcpListeners":[],
            "ctlmgrProcessObserved":False,"supervisorProcessObserved":False,
            "supervisorLauncherExitCode":0,
        }
        self.assertEqual(r2.classify(x), "E2_SERVICE_TARGET_EXITED")

    def test_http_dedupe(self):
        x = {"scheme":"http","port":80,"curlExitCode":0,"httpStatus":200,"bodyBytes":10,"responseMarkers":[]}
        self.assertEqual(r2._dedupe_http([x,x]), [x])


if __name__ == "__main__":
    unittest.main()
