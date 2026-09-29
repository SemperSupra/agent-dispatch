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
SCRIPT = SCRIPTS / "truenas_middleware_litellm_foundry_probe.py"
SPEC = importlib.util.spec_from_file_location("litellm_t6_probe", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


CONFIG = """model_list:
  - model_name: fixture
    litellm_params:
      model: openai/gpt-4o-mini
      api_key: os.environ/TEST_PROVIDER_KEY
litellm_settings:
  drop_params: true
"""


class LiteLlmT6ContractTests(unittest.TestCase):
    def control_dir(self, root, *, image=None, secret_read_only=True, product_head=None):
        d = pathlib.Path(root)
        (d / "runtime-fixtures").mkdir()
        (d / "runtime-fixtures" / "proxy_server_config.yaml").write_text(
            CONFIG, encoding="utf-8"
        )
        compose = {
            "services": {
                "litellm": {
                    "image": image or MOD.EXPECTED_IMAGE,
                    "environment": {
                        "SEMPER_SECRET_DIR": "/run/secrets/semper-env",
                    },
                    "volumes": [
                        {
                            "type": "bind",
                            "source": MOD.CONFIG_DIR,
                            "target": "/config",
                            "read_only": True,
                        },
                        {
                            "type": "bind",
                            "source": MOD.SECRET_DIR,
                            "target": "/run/secrets/semper-env",
                            "read_only": secret_read_only,
                        },
                    ],
                    "ports": [{
                        "target": 4000,
                        "published": str(MOD.APP_GUEST_PORT),
                    }],
                    "healthcheck": {
                        "test": ["CMD", "curl", "-f", "http://127.0.0.1:4000/health/liveliness"],
                    },
                }
            }
        }
        digest = MOD.canonical_sha256(compose)
        (d / "litellm.compose.json").write_text(
            json.dumps(compose), encoding="utf-8"
        )
        index = {
            "schema": "semper-supra.litellm-truenas-foundry-control/1",
            "foundry": {"commit": MOD.EXPECTED_FOUNDRY_COMMIT},
            "product_source": {
                "head": product_head or MOD.EXPECTED_PRODUCT_HEAD,
            },
            "public_projection": {"head": MOD.EXPECTED_PUBLIC_PROJECTION},
            "truenas_apps": {
                "commit": MOD.EXPECTED_TRUENAS_APPS_COMMIT,
                "library_version": MOD.EXPECTED_LIBRARY_VERSION,
                "library_hash": MOD.EXPECTED_LIBRARY_HASH,
            },
            "appliance": {"reference": MOD.EXPECTED_IMAGE},
            "runtime": {
                "app_name": MOD.APP_NAME,
                "config_dir": MOD.CONFIG_DIR,
                "secret_dir": MOD.SECRET_DIR,
                "published_port": MOD.APP_GUEST_PORT,
            },
            "compose_path": "litellm.compose.json",
            "compose_sha256": digest,
            "fixture_config_path": "runtime-fixtures/proxy_server_config.yaml",
            "fixture_config_sha256": MOD.EXPECTED_CONFIG_SHA256,
            "synthetic_secret": {
                "name": MOD.SECRET_NAME,
                "sha256": MOD.EXPECTED_SECRET_SHA256,
            },
        }
        (d / "index.json").write_text(json.dumps(index), encoding="utf-8")
        return digest

    def test_accepts_exact_litellm_control(self):
        with tempfile.TemporaryDirectory() as td:
            expected = self.control_dir(td)
            index, compose, digest, config = MOD.load_control(
                pathlib.Path(td), MOD.EXPECTED_FOUNDRY_COMMIT
            )
        self.assertEqual(expected, digest)
        self.assertEqual(index["appliance"]["reference"], MOD.EXPECTED_IMAGE)
        self.assertEqual(sorted(compose["services"]), ["litellm"])
        self.assertEqual(MOD.file_sha256(config), MOD.EXPECTED_CONFIG_SHA256)

    def test_rejects_image_drift(self):
        with tempfile.TemporaryDirectory() as td:
            self.control_dir(td, image="ghcr.io/sempersupra/litellm-appliance:latest")
            with self.assertRaises(RuntimeError):
                MOD.load_control(pathlib.Path(td), MOD.EXPECTED_FOUNDRY_COMMIT)

    def test_rejects_writable_s1_mount(self):
        with tempfile.TemporaryDirectory() as td:
            self.control_dir(td, secret_read_only=False)
            with self.assertRaises(RuntimeError):
                MOD.load_control(pathlib.Path(td), MOD.EXPECTED_FOUNDRY_COMMIT)

    def test_rejects_product_source_drift(self):
        with tempfile.TemporaryDirectory() as td:
            self.control_dir(td, product_head="0" * 40)
            with self.assertRaises(RuntimeError):
                MOD.load_control(pathlib.Path(td), MOD.EXPECTED_FOUNDRY_COMMIT)

    def test_probe_uses_public_upload_and_product_lifecycle_oracles(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"/_upload/"', text)
        self.assertIn('"method": "filesystem.put"', text)
        self.assertIn('"app.create"', text)
        self.assertIn('"app.config"', text)
        self.assertIn('"app.stop"', text)
        self.assertIn('"app.start"', text)
        self.assertIn('"app.delete"', text)
        self.assertIn("/health/liveliness", text)
        self.assertNotIn("filesystem.file_receive", text)


if __name__ == "__main__":
    unittest.main()
