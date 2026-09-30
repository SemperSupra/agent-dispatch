#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = HERE / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "truenas_middleware_foundry_control_probe.py"
SPEC = importlib.util.spec_from_file_location("t6_probe", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class FoundryT6ContractTests(unittest.TestCase):
    def control_dir(self, root, compose=None, runtime_safe=True):
        compose = compose or {
            "services": {
                "element-web": {
                    "image": "ghcr.io/element-hq/element-web:v1.12.26",
                    "ports": [{"target": 8080, "published": "8080"}],
                    "tmpfs": ["/etc/nginx/conf.d"],
                }
            }
        }
        digest = MOD.canonical_sha256(compose)
        d = pathlib.Path(root)
        (d / "element-web--basic-values.compose.json").write_text(
            json.dumps(compose), encoding="utf-8"
        )
        index = {
            "schema": "truenas-foundry-materialized-controls/v1",
            "upstream": {
                "repository": "https://github.com/truenas/apps.git",
                "ref": MOD.EXPECTED_UPSTREAM_REF,
                "train": "community",
                "library_version": MOD.EXPECTED_LIBRARY_VERSION,
                "library_hash": MOD.EXPECTED_LIBRARY_HASH,
            },
            "controls": [{
                "app": "element-web",
                "test_file": "basic-values.yaml",
                "primary_service": "element-web",
                "compose_path": "element-web--basic-values.compose.json",
                "compose_sha256": digest,
                "runtime_safe": runtime_safe,
                "qualification_role": MOD.EXPECTED_ROLE,
            }],
        }
        (d / "index.json").write_text(json.dumps(index), encoding="utf-8")
        return digest

    def test_selects_exact_runtime_safe_control_and_checks_identity(self):
        with tempfile.TemporaryDirectory() as td:
            expected = self.control_dir(td)
            index, control, compose, digest = MOD.load_control(
                pathlib.Path(td), MOD.EXPECTED_ROLE
            )
        self.assertEqual(digest, expected)
        self.assertEqual(control["app"], "element-web")
        self.assertEqual(sorted(compose["services"]), ["element-web"])
        self.assertEqual(index["upstream"]["ref"], MOD.EXPECTED_UPSTREAM_REF)

    def test_rejects_fixture_host_path(self):
        compose = {
            "services": {
                "element-web": {
                    "image": "example:tag",
                    "volumes": [{
                        "type": "bind",
                        "source": "/opt/tests/mnt/example",
                        "target": "/data",
                    }],
                }
            }
        }
        with tempfile.TemporaryDirectory() as td:
            self.control_dir(td, compose=compose)
            with self.assertRaises(RuntimeError):
                MOD.load_control(pathlib.Path(td), MOD.EXPECTED_ROLE)

    def test_rejects_control_not_explicitly_runtime_safe(self):
        with tempfile.TemporaryDirectory() as td:
            self.control_dir(td, runtime_safe=False)
            with self.assertRaises(RuntimeError):
                MOD.load_control(pathlib.Path(td), MOD.EXPECTED_ROLE)

    def test_script_is_exact_version_and_source_pinned(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"', text)
        self.assertIn(MOD.EXPECTED_UPSTREAM_REF, text)
        self.assertIn(MOD.EXPECTED_LIBRARY_HASH, text)
        self.assertIn('"app.create"', text)
        self.assertIn('"app.config"', text)
        self.assertIn('"app.delete"', text)
        self.assertIn("config_matches_foundry", text)
        self.assertIn("image_mutability_limitation", text)


if __name__ == "__main__":
    unittest.main()
