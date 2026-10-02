import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_supervisor_runtime.py"
spec = importlib.util.spec_from_file_location("fritz_e2_r1", SCRIPT)
r1 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r1)


class SupervisorRuntimeTests(unittest.TestCase):
    def test_classification_login(self):
        x = {"httpAttempts":[{"httpStatus":200,"responseMarkers":["session_info"]}]}
        self.assertEqual(r1.classify(x), "E2_LOGIN_HTTP_SUPPORTED")

    def test_classification_ctlmgr_listener(self):
        x = {"httpAttempts":[],"ctlmgrTcpListeners":[80],"ctlmgrProcessCountAfterStart":1}
        self.assertEqual(r1.classify(x), "E2_CTLMGR_LISTENER_OBSERVED")

    def test_classification_ctlmgr_started(self):
        x = {"httpAttempts":[],"ctlmgrTcpListeners":[],"ctlmgrProcessCountAfterStart":1}
        self.assertEqual(r1.classify(x), "E2_CTLMGR_STARTED_NO_LISTENER")

    def test_classification_svctl_rejected(self):
        x = {
            "httpAttempts":[],"ctlmgrTcpListeners":[],
            "ctlmgrProcessCountAfterStart":0,
            "svctlAttempted":True,"svctlExitCode":1,
            "supervisorProcessCountBeforeSvctl":1,
        }
        self.assertEqual(r1.classify(x), "E2_SUPERVISOR_RUNNING_SVCTL_REJECTED")

    def test_classification_supervisor_not_live(self):
        x = {
            "httpAttempts":[],"ctlmgrTcpListeners":[],
            "ctlmgrProcessCountAfterStart":0,
            "svctlAttempted":False,
            "supervisorProcessCountBeforeSvctl":0,
        }
        self.assertEqual(r1.classify(x), "E2_SUPERVISOR_NOT_LIVE")

    def test_missing_paths(self):
        raw = 'open("/var/run/x",0) = -1 errno=2 (No such file or directory)\n'
        self.assertEqual(r1.parse_missing_paths(raw), [{"path":"/var/run/x","count":1}])


if __name__ == "__main__":
    unittest.main()
