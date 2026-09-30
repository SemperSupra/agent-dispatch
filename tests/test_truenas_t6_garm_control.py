from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "truenas_middleware_garm_t6_probe.py"
SPEC = importlib.util.spec_from_file_location("garm_t6_probe", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class GarmT6ControlTests(unittest.TestCase):
    def sample_compose(self):
        service = {
            "image": MOD.EXPECTED_IMAGE,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges=true"],
            "privileged": False,
        }
        return {
            "services": {
                "garm": dict(service),
                "garm-config-seed": dict(service),
            },
            "configs": {
                MOD.BOOTSTRAP_CONFIG: {"content": MOD.BOOTSTRAP_PLACEHOLDER},
                MOD.TLS_CERT_CONFIG: {"content": MOD.TLS_PREFIX + MOD.TLS_CERT_CONFIG},
                MOD.TLS_KEY_CONFIG: {"content": MOD.TLS_PREFIX + MOD.TLS_KEY_CONFIG},
            },
        }

    def test_probe_contract_keeps_github_and_physical_boundaries_explicit(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"github_credentials_present": False',
            '"github_jit_registration_exercised": False',
            '"physical_truenas_mutation": False',
            '"capacity_promotion": False',
            '"secret_values_recorded": False',
            "EXPECTED_PROVIDER_SOURCE",
            "EXPECTED_CONTROLLER_SOURCE",
        ):
            self.assertIn(required, text)
        self.assertNotIn("GITHUB_APP_PRIVATE_KEY=", text)
        self.assertNotIn("local-truenas-linux-general", text)

    def test_probe_binds_controller_persistence_restart_and_cleanup(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"app.create"',
            '"app.stop"',
            '"app.start"',
            '"app.delete"',
            '"pool.dataset.delete"',
            "EXPECTED_CONFIG_PATH",
            "EXPECTED_DB_PATH",
            "https_ui_probe",
            '"zero_residue": True',
            "secret_normalized_compose_readback_sha256",
            "restart_compose_identity_preserved",
        ):
            self.assertIn(required, text)

    def test_normalization_restores_retained_placeholders(self):
        compose = self.sample_compose()
        compose["configs"][MOD.BOOTSTRAP_CONFIG]["content"] = "runtime-bootstrap"
        compose["configs"][MOD.TLS_CERT_CONFIG]["content"] = "runtime-cert"
        compose["configs"][MOD.TLS_KEY_CONFIG]["content"] = "runtime-key"
        normalized = MOD.normalize_secret_configs(compose)
        self.assertEqual(
            normalized["configs"][MOD.BOOTSTRAP_CONFIG]["content"],
            MOD.BOOTSTRAP_PLACEHOLDER,
        )
        self.assertEqual(
            normalized["configs"][MOD.TLS_CERT_CONFIG]["content"],
            MOD.TLS_PREFIX + MOD.TLS_CERT_CONFIG,
        )
        self.assertEqual(
            normalized["configs"][MOD.TLS_KEY_CONFIG]["content"],
            MOD.TLS_PREFIX + MOD.TLS_KEY_CONFIG,
        )

    def test_workflow_routes_exact_garm_export_through_existing_t6_selector(self):
        workflow = (ROOT / ".github" / "workflows" / "gha-kvm-system-rdte.yml").read_text(encoding="utf-8")
        harness = (ROOT / "scripts" / "gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        self.assertIn(
            "export-garm-t6-control.yml@34a0759fe390d7a92b270a599b6584f8949c6d07",
            workflow,
        )
        self.assertIn("name: garm-truenas-t6-control", workflow)
        self.assertIn("needs.changes.outputs.truenas_t6_product == 'garm'", workflow)
        self.assertIn("packages: read", workflow)
        self.assertIn('T6_PRODUCT\" == \"garm', harness)
        self.assertIn("truenas_middleware_garm_t6_probe.py", harness)
        self.assertIn("GARM_HOSTFWD", harness)
        self.assertIn("-:30880", harness)

    def test_load_control_rejects_foundry_drift(self):
        compose = self.sample_compose()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            deployment = {
                "artifact_sha256": "a" * 64,
                "materialization_identity": "sha256:" + "b" * 64,
            }
            control = {
                "schema": MOD.SCHEMA,
                "foundry_ref": "a" * 40,
                "appliance_reference": MOD.EXPECTED_IMAGE,
                "controller_source": MOD.EXPECTED_CONTROLLER_SOURCE,
                "provider_source": MOD.EXPECTED_PROVIDER_SOURCE,
                "private_secrets_captured": False,
                "fixture_secret_values_retained": False,
                "github_credentials_present": False,
                "runtime_compose_sha256": MOD.canonical_sha256(compose),
                "deployment_artifact_sha256": deployment["artifact_sha256"],
                "materialization_identity": deployment["materialization_identity"],
                "runtime": {
                    "app_name": MOD.EXPECTED_APP_NAME,
                    "config_root": MOD.EXPECTED_CONFIG_DIR,
                    "host_port": 30880,
                    "bootstrap_replacement": MOD.BOOTSTRAP_CONFIG,
                },
            }
            (root / "compose.json").write_text(json.dumps(compose), encoding="utf-8")
            (root / "deployment.json").write_text(json.dumps(deployment), encoding="utf-8")
            (root / "control.json").write_text(json.dumps(control), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Foundry source ref drifted"):
                MOD.load_control(root, "b" * 40)


if __name__ == "__main__":
    unittest.main()
