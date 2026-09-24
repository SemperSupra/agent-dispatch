import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_f3_useful_work",
    ROOT / "scripts" / "github_runner_firecracker_f3_useful_work.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerF3UsefulWorkTests(unittest.TestCase):
    def test_known_result(self):
        data = b"one two\nthree\n"
        expected = MOD.expected_result(data)
        self.assertEqual(expected["bytes"], len(data))
        self.assertEqual(expected["lines"], 2)
        self.assertEqual(expected["words"], 3)
        self.assertEqual(expected["fnv1a64"], f"{MOD.fnv1a64(data):016x}")

    def test_workload_fixture_is_bounded(self):
        data = MOD.DEFAULT_INPUT.read_bytes()
        self.assertGreater(len(data), 0)
        self.assertLessEqual(len(data), 4096)

    def test_capsule_contains_separate_candidate_and_input(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            init_bin = root / "init"
            candidate_bin = root / "candidate"
            out = root / "initrd.cpio"
            init_bin.write_bytes(b"init-binary")
            candidate_bin.write_bytes(b"candidate-binary")
            MOD.build_initramfs(init_bin, candidate_bin, b"input\n", out)
            payload = out.read_bytes()
        self.assertIn(b"work/candidate\0", payload)
        self.assertIn(b"candidate-binary", payload)
        self.assertIn(b"work/input.txt\0", payload)
        self.assertIn(b"input\n", payload)

    def test_result_regex_parses_candidate_timing(self):
        sample = (
            "FIRECRACKER_F3_CANDIDATE_RESULT bytes=9 lines=1 words=2 "
            "fnv1a64=0123456789abcdef work_ns=12345"
        )
        match = MOD.RESULT_RE.search(sample)
        self.assertIsNotNone(match)
        self.assertEqual(int(match.group(5)), 12345)


if __name__ == "__main__":
    unittest.main()
