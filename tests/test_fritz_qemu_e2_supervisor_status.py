import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_supervisor_status.py"
spec = importlib.util.spec_from_file_location("fritz_e2_r3", SCRIPT)
r3 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r3)


class SupervisorStatusTests(unittest.TestCase):
    def test_exact_supervisor_argv(self):
        self.assertEqual(
            r3.supervisor_guest_argv(),
            ["/bin/supervisor", "/lib/systemd/system", "ctlmgr.service"],
        )

    def test_exact_status_argv(self):
        self.assertEqual(
            r3.svctl_status_guest_argv(),
            ["/bin/svctl", "status", "ctlmgr"],
        )

    def test_classification_login(self):
        x = {"httpAttempts":[{"httpStatus":200,"responseMarkers":["session_info"]}]}
        self.assertEqual(r3.classify(x), "E2_LOGIN_HTTP_SUPPORTED")

    def test_classification_listener(self):
        x = {
            "httpAttempts":[],
            "ctlmgrTcpListenersAfterStatus":[80],
            "ctlmgrProcessObservedAfterStatus":True,
        }
        self.assertEqual(r3.classify(x), "E2_CTLMGR_LISTENER_OBSERVED")

    def test_status_ok_inactive(self):
        x = {
            "httpAttempts":[],
            "ctlmgrTcpListenersAfterStatus":[],
            "ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":True,
            "svctlStatusAttempted":True,
            "svctlStatusExitCode":0,
            "controlSocketBeforeStatus":{"exists":True,"isUnixSocket":True},
        }
        self.assertEqual(r3.classify(x), "E2_SVCTL_STATUS_OK_CTLMGR_NOT_RUNNING")

    def test_socket_present_status_rejected(self):
        x = {
            "httpAttempts":[],
            "ctlmgrTcpListenersAfterStatus":[],
            "ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":True,
            "svctlStatusAttempted":True,
            "svctlStatusExitCode":1,
            "controlSocketBeforeStatus":{"exists":True,"isUnixSocket":True},
        }
        self.assertEqual(
            r3.classify(x),
            "E2_CTRL_SOCKET_PRESENT_SVCTL_STATUS_REJECTED",
        )

    def test_socket_not_observed_status_failed(self):
        x = {
            "httpAttempts":[],
            "ctlmgrTcpListenersAfterStatus":[],
            "ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":True,
            "svctlStatusAttempted":True,
            "svctlStatusExitCode":1,
            "controlSocketBeforeStatus":{"exists":False,"isUnixSocket":False},
        }
        self.assertEqual(
            r3.classify(x),
            "E2_CTRL_SOCKET_NOT_OBSERVED_STATUS_FAILED",
        )

    def test_supervisor_not_live(self):
        x = {
            "httpAttempts":[],
            "ctlmgrTcpListenersAfterStatus":[],
            "ctlmgrProcessObservedAfterStatus":False,
            "supervisorProcessObservedBeforeStatus":False,
        }
        self.assertEqual(r3.classify(x), "E2_SUPERVISOR_NOT_LIVE")


if __name__ == "__main__":
    unittest.main()
