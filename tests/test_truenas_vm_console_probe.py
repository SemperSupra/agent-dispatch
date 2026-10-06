import unittest

from scripts.compute_guest_seed import SeedError
from scripts.truenas_vm_console_probe import _observe_nonce_frames, exact_marker, nonce_marker


class TrueNASVmConsoleProbeTests(unittest.TestCase):
    def test_nonce_marker_is_exact_and_ascii(self):
        self.assertEqual(
            nonce_marker("rep001nonceABCDEF12"),
            b"AGENT_DISPATCH_V1_NONCE=rep001nonceABCDEF12",
        )

    def test_nonce_marker_rejects_shell_metacharacters(self):
        with self.assertRaises(SeedError):
            nonce_marker("nonce;touch-pwned-1234")

    def test_exact_marker_accepts_windows_w1_marker(self):
        self.assertEqual(
            exact_marker("AGENT_DISPATCH_W1_NONCE=windowsw1nonce20261006"),
            b"AGENT_DISPATCH_W1_NONCE=windowsw1nonce20261006",
        )

    def test_exact_marker_rejects_non_ascii_and_controls(self):
        with self.assertRaises(SeedError):
            exact_marker("AGENT_DISPATCH_W1_NONCE=bad\nmarker")
        with self.assertRaises(SeedError):
            exact_marker("AGENT_DISPATCH_W1_NONCE=é")

    def test_idle_socket_timeout_is_transient_until_overall_deadline(self):
        marker = nonce_marker("rep003nonceABCDEF12")

        class FakeShell:
            def __init__(self):
                self.events = [
                    TimeoutError("timed out"),
                    (0x1, b'{"msg":"connected"}'),
                    (0x2, b"booting...\nAGENT_DISPATCH_V1_NONCE=rep003nonceABCDEF12\n"),
                ]

            def recv_payload(self):
                event = self.events.pop(0)
                if isinstance(event, BaseException):
                    raise event
                return event

        observed = _observe_nonce_frames(FakeShell(), marker, 1.0)
        self.assertTrue(observed["found"])
        self.assertTrue(observed["shell_connected"])
        self.assertEqual(observed["idle_read_timeouts"], 1)
        self.assertIn(marker.decode(), observed["console_tail"])


if __name__ == "__main__":
    unittest.main()
