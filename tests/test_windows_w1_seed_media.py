import json
import pathlib
import tempfile
import unittest

from scripts.windows_w1_seed_media import (
    REQUIRED_FILES,
    SEED_LABEL,
    WindowsW1SeedMediaError,
    validate_seed_dir,
    xorriso_command,
)


class WindowsW1SeedMediaTests(unittest.TestCase):
    def make_seed(self, root: pathlib.Path):
        (root / "Autounattend.xml").write_text("<unattend/>", encoding="utf-8")
        (root / "w1-bootstrap.ps1").write_text("Write-Output ok", encoding="utf-8")
        (root / "seed-contract.json").write_text(
            json.dumps({
                "schema": "windows-w1-unattend-seed/v1",
                "seed_volume_label": SEED_LABEL,
            }),
            encoding="utf-8",
        )

    def test_command_contains_exact_owned_seed_files_and_label(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self.make_seed(root)
            cmd = xorriso_command(root, root / "seed.iso")
            self.assertEqual(cmd[:3], ["xorriso", "-as", "mkisofs"])
            self.assertIn(SEED_LABEL, cmd)
            for name in REQUIRED_FILES:
                self.assertIn(str(root / name), cmd)

    def test_validation_hashes_all_required_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self.make_seed(root)
            hashes = validate_seed_dir(root)
            self.assertEqual(set(hashes), set(REQUIRED_FILES))
            self.assertTrue(all(len(v) == 64 for v in hashes.values()))

    def test_missing_file_and_contract_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self.make_seed(root)
            (root / "w1-bootstrap.ps1").unlink()
            with self.assertRaises(WindowsW1SeedMediaError):
                validate_seed_dir(root)

        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self.make_seed(root)
            (root / "seed-contract.json").write_text(
                json.dumps({"schema": "wrong", "seed_volume_label": SEED_LABEL}),
                encoding="utf-8",
            )
            with self.assertRaises(WindowsW1SeedMediaError):
                validate_seed_dir(root)


if __name__ == "__main__":
    unittest.main()
