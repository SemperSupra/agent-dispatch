import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "fixture", Path(__file__).resolve().parents[1] / "scripts/takeout_synthetic_fixture.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class SyntheticFixtureTests(unittest.TestCase):
    def test_three_files_range_halts_cleanup_and_restart_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = fixture.run(root)
            self.assertTrue(first["outcomes"]["range_resume"])
            self.assertTrue(first["halt_403"] and first["halt_429"])
            self.assertTrue(first["fixture_server_closed"])
            self.assertFalse(first["guest_qualified"])
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            second = fixture.run(root)
            self.assertEqual(set(second["outcomes"].values()), {"NOOP"})
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
            self.assertEqual(set(before), set(fixture.FILES) | {"retained-sentinel.txt"})

    def test_bytes_are_deterministic_and_tamper_is_not_noop(self):
        self.assertEqual({name: item["sha256"] for name, item in fixture.inventory().items()}, {
            "part-001.zip": "d995a1a20da62e99f8b34aa03e6f20ce6abebceae5d01e0a31ce3b831a149c09",
            "part-002.bin": "b9003892787a29135a21a43f382711802b1a63c3262eb8fe30809530dbee43a1",
            "part-003.zip": "8f24c7e002afa9e3e3acfe9c5b2d11c8ef2a0895aa341c8dd6adb1aedde8f8e2",
        })
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture.run(root)
            target = root / "part-002.bin"
            target.write_bytes(b"foreign")
            with self.assertRaisesRegex(ValueError, "existing content mismatch"):
                fixture.run(root)
            self.assertEqual(target.read_bytes(), b"foreign")

    def test_foreign_sentinel_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "retained-sentinel.txt").write_bytes(b"foreign")
            with self.assertRaisesRegex(ValueError, "sentinel changed"):
                fixture.run(root)
            self.assertEqual((root / "retained-sentinel.txt").read_bytes(), b"foreign")

    def test_fixture_cannot_be_used_as_external_downloader(self):
        for base, name in (("https://example.com", "part-001.zip"),
                           ("http://127.0.0.1:80", "../escape")):
            with self.assertRaisesRegex(ValueError, "synthetic input only"):
                fixture.download(base, name, Path("unused"))


if __name__ == "__main__":
    unittest.main()
