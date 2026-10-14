import importlib.util
from pathlib import Path
import tempfile
import json
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
            "part-001.zip": "0672ad5284db40d900ae07238fe3954eb3652aa31a1fdca9ac704b4d41d41d8c",
            "part-002.bin": "b9003892787a29135a21a43f382711802b1a63c3262eb8fe30809530dbee43a1",
            "part-003.zip": "c7450ea93a3b5f8bd145efc93d7116f82204bf9206a94a3b8e3279596e8b08dc",
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

    def test_state_identity_and_retention_after_temporary_state_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, state = root / "archive", root / "state"
            fixture.run(archive, state)
            receipt = json.loads((state / "state.json").read_text())
            self.assertEqual(receipt["files"], fixture.inventory())
            (state / "state.json").write_text('{}')
            with self.assertRaisesRegex(ValueError, "state identity mismatch"):
                fixture.run(archive, state)
            (state / "state.json").unlink()
            state.rmdir()
            self.assertFalse(state.exists())
            for name, data in fixture.FILES.items():
                self.assertEqual((archive / name).read_bytes(), data)
            self.assertEqual((archive / "retained-sentinel.txt").read_bytes(), fixture.SENTINEL)


if __name__ == "__main__":
    unittest.main()
