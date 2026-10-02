import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_overlay.py"
spec = importlib.util.spec_from_file_location("fritz_overlay", SCRIPT)
overlay = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(overlay)


class OverlayTests(unittest.TestCase):
    def test_destination_must_be_under_opt_supra(self):
        with self.assertRaises(ValueError):
            overlay.validate_guest_destination("/etc/rc.local")
        self.assertEqual(
            str(overlay.validate_guest_destination("/opt/supra/bin/x")),
            "/opt/supra/bin/x",
        )

    def test_parent_traversal_rejected(self):
        with self.assertRaises(ValueError):
            overlay.validate_guest_destination("/opt/supra/../etc/passwd")

    def test_canonical_manifest_hash_stable(self):
        a = {"b": 2, "a": 1}
        b = {"a": 1, "b": 2}
        self.assertEqual(overlay.canonical_sha256(a), overlay.canonical_sha256(b))

    def test_apply_refuses_stock_path_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "root"
            repo = pathlib.Path(td) / "repo"
            (root / "opt/supra/bin").mkdir(parents=True)
            (repo / "fixtures").mkdir(parents=True)
            (root / "opt/supra/bin/x").write_text("stock")
            (repo / "fixtures/x").write_text("new")
            manifest = {
                "operations": [{
                    "op": "copy_public_file",
                    "source": "fixtures/x",
                    "destination": "/opt/supra/bin/x",
                    "mode": "0755",
                    "requireDestinationAbsent": True,
                }]
            }
            with self.assertRaises(RuntimeError):
                overlay.apply_overlay(root, manifest, repo)

    def test_load_manifest_requires_no_semantic_change(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "m.json"
            p.write_text(json.dumps({
                "schemaVersion": 1,
                "semantics": {"stockSemanticsExpectedToChange": True},
                "operations": [{
                    "op": "copy_public_file",
                    "source": "fixtures/x",
                    "destination": "/opt/supra/bin/x",
                    "mode": "0755",
                    "requireDestinationAbsent": True,
                }],
            }))
            with self.assertRaises(ValueError):
                overlay.load_manifest(p)


if __name__ == "__main__":
    unittest.main()
