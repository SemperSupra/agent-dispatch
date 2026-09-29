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
SCRIPT = SCRIPTS / "truenas_middleware_litellm_t6_probe.py"
SPEC = importlib.util.spec_from_file_location("litellm_t6_probe", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


class LiteLlmT6ContractTests(unittest.TestCase):
    def make_control(self, root, *, image=None, secret_names=None):
        image = image or MOD.EXPECTED_APPLIANCE
        secret_names = secret_names or ["TEST_PROVIDER_KEY"]
        compose = {
            "services": {
                "litellm": {
                    "image": image,
                    "environment": {"SEMPER_SECRET_DIR": "/run/secrets/semper-env"},
                    "ports": [{"target": 4000, "published": "30401", "protocol": "tcp"}],
                    "volumes": [
                        {"type": "bind", "source": MOD.EXPECTED_CONFIG_DIR, "target": "/config", "read_only": True},
                        {"type": "bind", "source": MOD.EXPECTED_SECRET_DIR, "target": "/run/secrets/semper-env", "read_only": True},
                    ],
                }
            }
        }
        config = b"model_list: []\n"
        control = {
            "schema": MOD.EXPECTED_SCHEMA,
            "foundry_ref": MOD.EXPECTED_FOUNDRY_REF,
            "candidate": {
                "appliance_reference": MOD.EXPECTED_APPLIANCE,
                "appliance_digest": MOD.EXPECTED_APPLIANCE_DIGEST,
                "truenas_apps_commit": MOD.EXPECTED_TRUENAS_APPS_COMMIT,
                "truenas_lib_version": MOD.EXPECTED_LIBRARY_VERSION,
                "truenas_lib_hash": MOD.EXPECTED_LIBRARY_HASH,
            },
            "runtime": {
                "app_name": MOD.EXPECTED_APP_NAME,
                "guest_port": MOD.EXPECTED_GUEST_PORT,
                "config_dir": MOD.EXPECTED_CONFIG_DIR,
                "secret_dir": MOD.EXPECTED_SECRET_DIR,
                "config_file": MOD.EXPECTED_CONFIG_FILE,
                "fixture_secret_names": secret_names,
            },
            "artifacts": {
                "compose_canonical_sha256": MOD.canonical_sha256(compose),
                "config_sha256": MOD.sha256_bytes(config),
            },
            "secrets_captured": False,
        }
        root = pathlib.Path(root)
        (root / "control.json").write_text(json.dumps(control), encoding="utf-8")
        (root / "compose.json").write_text(json.dumps(compose), encoding="utf-8")
        (root / MOD.EXPECTED_CONFIG_FILE).write_bytes(config)
        return compose

    def test_loads_exact_litellm_control(self):
        with tempfile.TemporaryDirectory() as td:
            expected = self.make_control(td)
            control, compose, config, service = MOD.load_control(pathlib.Path(td))
        self.assertEqual(compose, expected)
        self.assertEqual(service, "litellm")
        self.assertEqual(control["foundry_ref"], MOD.EXPECTED_FOUNDRY_REF)
        self.assertEqual(config, b"model_list: []\n")

    def test_rejects_appliance_drift(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_control(td, image="example.invalid/litellm:latest")
            with self.assertRaises(RuntimeError):
                MOD.load_control(pathlib.Path(td))

    def test_rejects_secret_name_broadening(self):
        with tempfile.TemporaryDirectory() as td:
            self.make_control(td, secret_names=["TEST_PROVIDER_KEY", "OPENROUTER_MANAGEMENT_KEY"])
            with self.assertRaises(RuntimeError):
                MOD.load_control(pathlib.Path(td))

    def test_script_pins_supported_upload_and_lifecycle_boundaries(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"/_upload/"', text)
        self.assertIn('"filesystem.put"', text)
        self.assertIn('"filesystem.mkdir"', text)
        self.assertIn('("/mnt/rdtepool/litellm-t6", "750")', text)
        self.assertIn('(EXPECTED_CONFIG_DIR, "750")', text)
        self.assertIn('(EXPECTED_SECRET_DIR, "700")', text)
        self.assertIn('"raise_chmod_error": True', text)
        self.assertIn('"app.create"', text)
        self.assertIn('"app.stop"', text)
        self.assertIn('"app.start"', text)
        self.assertIn('"app.delete"', text)
        self.assertIn('"/health/liveliness"', text)
        self.assertIn('"/health/readiness"', text)
        self.assertIn(MOD.EXPECTED_APPLIANCE_DIGEST, text)
        self.assertNotIn("OPENROUTER_API_KEY", text)


    def test_workflow_and_harness_are_bound_to_exact_litellm_export(self):
        workflow = (HERE / ".github" / "workflows" / "gha-kvm-system-rdte.yml").read_text(encoding="utf-8")
        harness = (SCRIPTS / "gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        self.assertIn(
            "export-litellm-t6-control.yml@" + MOD.EXPECTED_FOUNDRY_REF,
            workflow,
        )
        self.assertIn("foundry_ref: " + MOD.EXPECTED_FOUNDRY_REF, workflow)
        self.assertIn("name: litellm-truenas-t6-control", workflow)
        self.assertIn('--foundry-commit "' + MOD.EXPECTED_FOUNDRY_REF + '"', workflow)
        self.assertNotIn("truenas-foundry-materialized-controls", workflow)
        self.assertIn('LITELLM_HOSTFWD=",hostfwd=tcp:127.0.0.1:', harness)
        self.assertIn('-:30401"', harness)
        self.assertIn(
            'python3 "$SCRIPT_DIR/truenas_middleware_litellm_t6_probe.py"',
            harness,
        )
        self.assertIn('--service-port "$LITELLM_HOST_PORT"', harness)
        self.assertNotIn(
            'python3 "$SCRIPT_DIR/truenas_middleware_foundry_control_probe.py"',
            harness,
        )



if __name__ == "__main__":
    unittest.main()
