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



    def test_fixed_trace_evidence(self):
        raw = (
            '101 openat(AT_FDCWD,"/lib/systemd/system/ctlmgr.service",O_RDONLY) = 3\n'
            '101 openat(AT_FDCWD,"/var/tmp/psupport.data",O_RDONLY) = -1 errno=2 (No such file or directory)\n'
            '101 execve("/usr/bin/ctlmgr",0x1,0x2) = -1 errno=2 (No such file or directory)\n'
        )
        e = r3.fixed_trace_evidence(raw)
        self.assertEqual(e["paths"]["ctlmgr_unit"]["hitCount"], 1)
        self.assertEqual(e["paths"]["ctlmgr_unit"]["successCount"], 1)
        self.assertEqual(e["paths"]["psupport_data"]["failureCount"], 1)
        self.assertEqual(e["ctlmgrExecveCount"], 1)

    def test_classification_unit_read_psupport_missing(self):
        x = {
            "httpAttempts": [],
            "ctlmgrProcessObserved": False,
            "fixedPathTrace": {
                "ctlmgrExecveCount": 0,
                "paths": {
                    "ctlmgr_unit": {"hitCount": 1},
                    "psupport_data": {"failureCount": 1},
                },
            },
        }
        self.assertEqual(r3.classify(x), "E2_CTLMGR_UNIT_READ_PSUPPORT_MISSING")

    def test_classification_ctlmgr_exec_attempted(self):
        x = {
            "httpAttempts": [],
            "ctlmgrProcessObserved": False,
            "fixedPathTrace": {"ctlmgrExecveCount": 1, "paths": {}},
        }
        self.assertEqual(r3.classify(x), "E2_CTLMGR_EXEC_ATTEMPTED")

if __name__ == "__main__":
    unittest.main()
