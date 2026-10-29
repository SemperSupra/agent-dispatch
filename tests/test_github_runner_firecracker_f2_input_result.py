import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_f2_input_result",
    ROOT / "scripts" / "github_runner_firecracker_f2_input_result.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerF2InputResultTests(unittest.TestCase):
    def test_known_fnv1a64_vector(self):
        self.assertEqual(MOD._fnv1a64(b""), 0xCBF29CE484222325)
        self.assertEqual(MOD._fnv1a64(b"a"), 0xAF63DC4C8601EC8C)

    def test_expected_marker_binds_length_and_computation(self):
        marker = MOD._expected_marker(b"abc")
        self.assertEqual(
            marker,
            "FIRECRACKER_F2_RESULT bytes=3 fnv1a64=e71fa2190541574b",
        )

    def test_initramfs_contains_bounded_input_member(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            init = root / "init"
            init.write_bytes(b"ELF-placeholder")
            out = root / "initrd.cpio"
            MOD._build_initramfs(init, b"bounded-input\n", out)
            payload = out.read_bytes()
        self.assertIn(b"work/input.txt\0", payload)
        self.assertIn(b"bounded-input\n", payload)
        self.assertIn(b"dev/console\0", payload)
        self.assertIn(b"TRAILER!!!\0", payload)

    def test_default_input_is_within_guardrail(self):
        data = MOD.DEFAULT_INPUT.read_bytes()
        self.assertGreater(len(data), 0)
        self.assertLessEqual(len(data), MOD.MAX_INPUT_BYTES)


if __name__ == "__main__":
    unittest.main()
