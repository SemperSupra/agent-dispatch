import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "g", ROOT / "scripts" / "github_runner_guest_receipt.py"
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class T(unittest.TestCase):
    def test_parse(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "x"
            p.write_text("A=1\nB=two\n")
            self.assertEqual(MOD.parse(p), {"A": "1", "B": "two"})

    def test_intval(self):
        self.assertEqual(MOD.intval("4"), 4)
        self.assertIsNone(MOD.intval(""))

    def test_select_release_asset_requires_unique_exact_prefix(self):
        release = {
            "assets": [
                {"name": "freebsd-15.1-riscv64.qcow2", "digest": "sha256:abc"},
                {"name": "freebsd-15.1-arm64.qcow2", "digest": "sha256:def"},
            ]
        }
        asset = MOD.select_release_asset(release, "freebsd", "15.1", "riscv64")
        self.assertEqual(asset["digest"], "sha256:abc")

    def test_filesystem_negative_is_not_oracle_failure(self):
        cap = MOD.capability(
            "filesystem:hardlink",
            False,
            "unsupported",
            negative="NEGATIVE_OBSERVATION",
        )
        self.assertEqual(cap["classification"], "NEGATIVE_OBSERVATION")


if __name__ == "__main__":
    unittest.main()
