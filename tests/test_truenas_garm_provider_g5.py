from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "truenas_middleware_garm_provider_g5_probe.py"
G3_SCRIPT = ROOT / "scripts" / "truenas_middleware_garm_provider_g3_probe.py"
SPEC = importlib.util.spec_from_file_location("garm_provider_g5_probe", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class GarmProviderG5Tests(unittest.TestCase):
    def matrix(self) -> dict:
        return {
            "schema": MOD.EXPECTED_MATRIX_SCHEMA,
            "provider_product_source": MOD.EXPECTED_PROVIDER_PRODUCT_SOURCE,
            "producer_source": "f" * 40,
            "runtime_inheritance_allowed": False,
            "source_oracles": {
                "exact_middleware_commits": True,
                "exact_git_blob_identities": True,
                "provider_method_surface_scan": True,
                "existing_25_04_1_contract_consistent": True,
                "runtime_inheritance_prohibited": True,
            },
            "targets": [
                {
                    "version": "25.10.7",
                    "system_version": "TrueNAS-25.10.7",
                    "middleware_ref": "TS-25.10.7",
                    "middleware_commit": "8ede398839710e56893d88ce85088139d8fab18e",
                    "source_equivalence_group": "goldeye-25.10.7-provider-control",
                    "source_blobs": {f"path-{i}": f"{i:040x}"[-40:] for i in range(7)},
                }
            ],
        }

    def test_matrix_binds_exact_row_and_prohibits_inheritance(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "garm-provider-truenas-g5-version-matrix.json"
            path.write_text(json.dumps(self.matrix()), encoding="utf-8")
            loaded = MOD.load_matrix(root, "f" * 40)
            row = MOD.select_row(
                loaded,
                "25.10.7",
                "8ede398839710e56893d88ce85088139d8fab18e",
            )
            self.assertEqual(row["system_version"], "TrueNAS-25.10.7")

            with self.assertRaisesRegex(RuntimeError, "middleware commit drifted"):
                MOD.select_row(loaded, "25.10.7", "0" * 40)

            bad = self.matrix()
            bad["runtime_inheritance_allowed"] = True
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "prohibit runtime support inheritance"):
                MOD.load_matrix(root, "f" * 40)

    def test_matrix_rejects_false_source_oracle(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bad = self.matrix()
            bad["source_oracles"]["exact_git_blob_identities"] = False
            (root / "garm-provider-truenas-g5-version-matrix.json").write_text(
                json.dumps(bad), encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "source oracles are not all true"):
                MOD.load_matrix(root, "f" * 40)

    def test_g3_lifecycle_is_version_parameterized_without_changing_default(self):
        text = G3_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('p.add_argument("--expected-version", default=EXPECTED_VERSION)', text)
        self.assertIn('"expected_version": a.expected_version', text)
        self.assertIn("if version != a.expected_version:", text)

    def test_wrapper_passes_exact_system_version_to_underlying_lifecycle(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"--expected-version", expected_system_version', text)
        self.assertIn('"--fixture-producer-commit", args.fixture_producer_commit', text)
        self.assertIn('"provider_lifecycle_supported": True', text)
        self.assertIn('"runtime_inheritance_prohibited": True', text)
        self.assertIn('"zero_unintended_residue": True', text)

    def test_public_boundary_remains_explicit(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"github_credentials_present": False',
            '"github_jit_registration_exercised": False',
            '"private_repository_execution": False',
            '"physical_truenas_mutation": False',
            '"capacity_promotion": False',
        ):
            self.assertIn(required, text)
        self.assertNotIn("GITHUB_TOKEN", text)
        self.assertNotIn("GH_TOKEN", text)


if __name__ == "__main__":
    unittest.main()
