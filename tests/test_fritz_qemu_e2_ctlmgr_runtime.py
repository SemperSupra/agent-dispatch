import importlib.util
import pathlib
import unittest

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "fritz_qemu_e2_ctlmgr_runtime.py"
)
spec = importlib.util.spec_from_file_location("fritz_e2_runtime", SCRIPT)
runtime = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(runtime)


class E2RuntimeTests(unittest.TestCase):
    def test_response_markers_are_bounded(self):
        data = b"<?xml?><SessionInfo><SID>0000</SID><Challenge>x</Challenge></SessionInfo>"
        self.assertEqual(
            runtime.fixed_response_markers(data),
            ["session_info", "sid", "challenge"],
        )

    def test_missing_path_parser_only_keeps_absolute_paths(self):
        raw = (
            '1 openat(AT_FDCWD,"/var/flash/ar7.cfg",0) = -1 errno=2 '
            '(No such file or directory)\n'
            '2 openat(AT_FDCWD,"relative.cfg",0) = -1 errno=2 '
            '(No such file or directory)\n'
            '3 stat("/var/flash/ar7.cfg",0) = -1 errno=2 '
            '(No such file or directory)\n'
        )
        self.assertEqual(
            runtime.parse_missing_paths(raw),
            [{"path": "/var/flash/ar7.cfg", "count": 2}],
        )

    def test_tcp_port_extraction(self):
        sample = (
            "LISTEN 0 128 127.0.0.1:80 0.0.0.0:*\n"
            "LISTEN 0 128 0.0.0.0:49000 0.0.0.0:*\n"
        )
        self.assertEqual(runtime.extract_tcp_ports(sample), [80, 49000])

    def test_classification_login_pass(self):
        result = {
            "tcpListeners": [80],
            "targetRunningAtObservation": True,
            "httpAttempts": [{
                "httpStatus": 200,
                "responseMarkers": ["session_info", "sid"],
            }],
        }
        self.assertEqual(
            runtime.classify_namespace_result(result),
            "E2_LOGIN_HTTP_SUPPORTED",
        )

    def test_classification_listener_only(self):
        result = {
            "tcpListeners": [80],
            "targetRunningAtObservation": True,
            "httpAttempts": [],
        }
        self.assertEqual(
            runtime.classify_namespace_result(result),
            "E2_LISTENER_OBSERVED",
        )

    def test_classification_running_without_listener(self):
        result = {
            "tcpListeners": [],
            "targetRunningAtObservation": True,
            "httpAttempts": [],
        }
        self.assertEqual(
            runtime.classify_namespace_result(result),
            "E2_PROCESS_RUNNING_NO_LISTENER",
        )


if __name__ == "__main__":
    unittest.main()
