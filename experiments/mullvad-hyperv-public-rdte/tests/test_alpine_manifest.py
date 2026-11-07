"""Offline trust-boundary tests for fixed Alpine SHA256 public manifest."""
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tools.alpine_manifest import FILENAME, parse_manifest

DIGEST = "0123456789abcdef" * 4


class ManifestTests(unittest.TestCase):
    def test_exact_target_positive_control(self):
        self.assertEqual(parse_manifest((DIGEST + "  " + FILENAME + "\n").encode()), DIGEST)

    def test_wrong_filename_and_version_rejected(self):
        for file in ("alpine-virt-3.24.1-x86_64.iso", "alpine-standard-3.24.2-x86_64.iso",
                     FILENAME + ".sh", FILENAME + "\nmalicious"):
            with self.subTest(filename=file):
                with self.assertRaises(ValueError):
                    parse_manifest((DIGEST + "  " + file).encode())

    def test_oversize_or_nonascii_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(b"A" * 513)
        with self.assertRaises(ValueError):
            parse_manifest(bytes([0xff]) * 5)

    def test_malformed_or_partial_digest_rejected(self):
        for value in ("x" * 64, "f" * 63, "f" * 65, "", "\n", "f" * 64 + "extra"):
            with self.subTest(digest=value):
                with self.assertRaises(ValueError):
                    parse_manifest((value + "  " + FILENAME).encode())

    def test_no_second_line_or_shell_payload_accepted(self):
        with self.assertRaises(ValueError):
            parse_manifest((DIGEST + "  " + FILENAME + "\n" + DIGEST + "  other.iso").encode())
        with self.assertRaises(ValueError):
            parse_manifest((DIGEST + "  " + FILENAME + "; echo bad").encode())


if __name__ == "__main__":
    unittest.main()
