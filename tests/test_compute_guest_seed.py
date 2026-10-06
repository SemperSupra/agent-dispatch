import pathlib
import tempfile
import unittest

from scripts.compute_guest_seed import PREFIX, SeedError, render_seed, write_seed


class ComputeGuestSeedTests(unittest.TestCase):
    def test_seed_is_deterministic_and_serial_nonce_is_external(self):
        nonce = "rep001nonceABCDEF12"
        meta, user = render_seed(nonce, "rdte-v1-rep001")
        self.assertEqual(meta, "instance-id: rdte-v1-rep001\nlocal-hostname: rdtev1\n")
        self.assertTrue(user.startswith("#!/bin/sh\nset -eu\n"))
        self.assertIn(PREFIX, user)
        self.assertIn(">/dev/ttyS0", user)
        self.assertIn(">/dev/console", user)
        self.assertNotIn("curl ", user)
        self.assertNotIn("wget ", user)

    def test_seed_rejects_shell_metacharacters(self):
        for bad in ("short", "nonce;touch-pwned-1234", "$(id)-abcdefghijkl"):
            with self.assertRaises(SeedError):
                render_seed(bad, "rdte-v1-rep001")

    def test_write_seed_uses_expected_names_and_executable_userdata(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            write_seed(root, "rep002nonceABCDEF12", "rdte-v1-rep002")
            self.assertTrue((root / "meta-data").is_file())
            self.assertTrue((root / "user-data").is_file())
            self.assertEqual((root / "user-data").stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
