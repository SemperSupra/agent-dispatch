import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "github_runner_firecracker_p3_same_host_handoff",
    ROOT / "scripts" / "github_runner_firecracker_p3_same_host_handoff.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FirecrackerP3HandoffTests(unittest.TestCase):
    def test_heartbeat_parser(self):
        lines = [
            "FIRECRACKER_P3_READY counter=0",
            "FIRECRACKER_P3_HEARTBEAT counter=1",
            "noise",
            "FIRECRACKER_P3_HEARTBEAT counter=2",
        ]
        self.assertEqual(MOD._all_heartbeat_values(lines), [1, 2])

    def test_regexes_distinguish_ready_heartbeat_done(self):
        self.assertIsNotNone(MOD.READY_RE.search("FIRECRACKER_P3_READY counter=0"))
        self.assertIsNotNone(MOD.HEARTBEAT_RE.search("FIRECRACKER_P3_HEARTBEAT counter=7"))
        self.assertIsNotNone(MOD.DONE_RE.search("FIRECRACKER_P3_DONE counter=20"))

    def test_guest_source_is_device_free_handoff_fixture(self):
        source = MOD.INIT_SOURCE.read_text()
        self.assertIn("FIRECRACKER_P3_READY", source)
        self.assertIn("FIRECRACKER_P3_HEARTBEAT", source)
        self.assertIn("FIRECRACKER_P3_DONE", source)


if __name__ == "__main__":
    unittest.main()
