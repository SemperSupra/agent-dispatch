import unittest

from scripts.compute_guest_seed import SeedError
from scripts.truenas_vm_console_probe import nonce_marker


class TrueNASVmConsoleProbeTests(unittest.TestCase):
    def test_nonce_marker_is_exact_and_ascii(self):
        self.assertEqual(
            nonce_marker("rep001nonceABCDEF12"),
            b"AGENT_DISPATCH_V1_NONCE=rep001nonceABCDEF12",
        )

    def test_nonce_marker_rejects_shell_metacharacters(self):
        with self.assertRaises(SeedError):
            nonce_marker("nonce;touch-pwned-1234")


if __name__ == "__main__":
    unittest.main()
