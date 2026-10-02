import hashlib
import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_qemu_e2_wire_digest.py"
SPEC = importlib.util.spec_from_file_location("r9", SCRIPT)
r9 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r9)


class R9Tests(unittest.TestCase):
    def test_parse_control_wire_only(self):
        trace = r"""
123 socket(AF_UNIX, SOCK_STREAM, 0) = 3
123 connect(3, {sa_family=AF_UNIX, sun_path="/tmp/supervisor.ctrl.socket"}, 110) = 0
123 sendto(3, "\x01\x02", 2, MSG_NOSIGNAL, NULL, 0) = 2
123 write(1, "\x41", 1) = 1
123 read(3, "\xaa\xbb", 2) = 2
123 close(3) = 0
"""
        got = r9.parse_wire_trace(trace)
        self.assertTrue(got["captureComplete"])
        self.assertEqual(got["controlConnectCount"], 1)
        self.assertEqual(got["request"]["totalBytes"], 2)
        self.assertEqual(got["response"]["totalBytes"], 2)
        self.assertEqual(got["request"]["sha256"], hashlib.sha256(b"\x01\x02").hexdigest())
        self.assertEqual(got["response"]["sha256"], hashlib.sha256(b"\xaa\xbb").hexdigest())
        self.assertEqual([x["direction"] for x in got["eventSequence"]], ["request", "response"])
        self.assertFalse(got["payloadPublished"])
        self.assertFalse(got["rawTracePublished"])

    def test_pid_prefix_and_chunk_order(self):
        trace = r"""
[pid 77] connect(5, {sa_family=AF_UNIX, sun_path="/tmp/supervisor.ctrl.socket"}, 110) = 0
[pid 77] sendto(5, "\x01", 1, MSG_NOSIGNAL, NULL, 0) = 1
[pid 77] sendto(5, "\x02\x03", 2, MSG_NOSIGNAL, NULL, 0) = 2
[pid 77] read(5, "\x10", 1) = 1
[pid 77] read(5, "\x11\x12", 2) = 2
"""
        got = r9.parse_wire_trace(trace)
        self.assertTrue(got["captureComplete"])
        self.assertEqual(got["request"]["totalBytes"], 3)
        self.assertEqual(got["response"]["totalBytes"], 3)
        self.assertEqual(got["request"]["sha256"], hashlib.sha256(b"\x01\x02\x03").hexdigest())
        self.assertEqual(got["response"]["sha256"], hashlib.sha256(b"\x10\x11\x12").hexdigest())
        self.assertEqual([x["ordinal"] for x in got["eventSequence"]], [1, 2, 3, 4])

    def test_truncation_fails_capture(self):
        trace = r"""
connect(3, {sa_family=AF_UNIX, sun_path="/tmp/supervisor.ctrl.socket"}, 110) = 0
sendto(3, "\x01", 4, MSG_NOSIGNAL, NULL, 0) = 4
read(3, "\xaa", 1) = 1
"""
        got = r9.parse_wire_trace(trace)
        self.assertFalse(got["captureComplete"])
        self.assertEqual(got["incompleteEventCount"], 1)

    def test_unsupported_control_io_fails_capture(self):
        trace = r"""
connect(3, {sa_family=AF_UNIX, sun_path="/tmp/supervisor.ctrl.socket"}, 110) = 0
sendmsg(3, {msg_name=NULL}, MSG_NOSIGNAL) = 4
read(3, "\xaa", 1) = 1
"""
        got = r9.parse_wire_trace(trace)
        self.assertFalse(got["captureComplete"])
        self.assertEqual(got["unsupportedControlIoCount"], 1)

    def test_summary_and_classification(self):
        def wire(req, rsp):
            return {
                "captureComplete": True,
                "request": {"totalBytes": len(req), "sha256": hashlib.sha256(req).hexdigest()},
                "response": {"totalBytes": len(rsp), "sha256": hashlib.sha256(rsp).hexdigest()},
            }

        runtime = {
            "probeCompleted": True,
            "ctlmgrProcessObserved": False,
            "preStatus": {"wireCapture": wire(b"status", b"same")},
            "start": {"wireCapture": wire(b"start", b"different")},
            "postStatus": {"wireCapture": wire(b"status", b"same")},
        }
        summary = r9.summarize_wire(runtime)
        self.assertTrue(summary["captureComplete"])
        self.assertTrue(summary["comparisons"]["prePostStatusRequestEqual"])
        self.assertTrue(summary["comparisons"]["prePostStatusResponseEqual"])
        self.assertTrue(summary["comparisons"]["startRequestDiffersFromStatus"])
        self.assertEqual(r9.classify(runtime, summary), "E2_R9_WIRE_CLASSES_DISTINGUISHED")


if __name__ == "__main__":
    unittest.main()
