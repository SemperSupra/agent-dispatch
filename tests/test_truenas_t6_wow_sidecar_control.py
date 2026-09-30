from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "truenas_middleware_wow_sidecar_t6_probe.py"
SPEC = importlib.util.spec_from_file_location("wow_t6_probe", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class WowSidecarT6ControlTests(unittest.TestCase):
    def test_probe_contract_is_public_fixture_only(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("production_credentials_present", text)
        self.assertIn('"public-fixture-only"', text)
        self.assertIn(MOD.EXPECTED_IMAGE, text)
        self.assertIn(MOD.EXPECTED_HELPER, text)
        self.assertIn(MOD.EXPECTED_FIXTURE_DATASET, text)
        self.assertIn('"execution_control_mutation_authorized": False', text)
        self.assertNotIn("GITHUB_APP_PRIVATE_KEY=", text)
        self.assertIn("PRIVATE_REPO_RE", text)
        self.assertNotIn("SemperSupra/wow-sidecar-private", text)
        self.assertNotIn("SemperSupra/agent-dispatch-private", text)

    def test_probe_binds_seed_permissions_restart_and_cleanup_oracles(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"filesystem.stat"',
            "EXPECTED_KEY_PATH",
            "EXPECTED_PROFILE_PATH",
            "EXPECTED_MARKER_PATH",
            '"0o400"',
            '"0o444"',
            '"app.create"',
            '"app.stop"',
            '"app.start"',
            '"app.delete"',
            '"pool.dataset.delete"',
            '"zero_residue": True',
            "compose_readback_sha256",
            "restart_compose_identity_preserved",
        ):
            self.assertIn(required, text)

    def test_workflow_routes_exact_wow_export_without_reopening_litellm_default(self):
        workflow = (ROOT / ".github" / "workflows" / "gha-kvm-system-rdte.yml").read_text(encoding="utf-8")
        harness = (ROOT / "scripts" / "gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        request = json.loads((ROOT / "config" / "truenas-rdte-run-request.json").read_text(encoding="utf-8"))

        self.assertIn(
            "export-wow-sidecar-t6-control.yml@68d08ce9561b0ccf68d2e7eb446a76514e1a8ed2",
            workflow,
        )
        self.assertIn("name: wow-sidecar-truenas-t6-control", workflow)
        self.assertIn("--t6-product", workflow)
        self.assertIn('"wow-sidecar"', harness)
        self.assertIn("truenas_middleware_wow_sidecar_t6_probe.py", harness)
        self.assertIn('T6_PRODUCT="litellm"', harness)
        self.assertIn(request["product"], {"litellm", "wow-sidecar", "garm", "garm-provider-g2"})
        if request["product"] == "wow-sidecar":
            self.assertEqual("t6", request["rung"])
            self.assertEqual("26.0.0-BETA.3", request["version"])
            self.assertEqual(396, request["authority_issue"])
            self.assertEqual(276, request["consumer_authority_issue"])

    def test_load_control_rejects_foundry_drift(self):
        compose = {
            "services": {
                "permissions": {"image": MOD.EXPECTED_HELPER},
                "wow-sidecar": {"image": MOD.EXPECTED_IMAGE},
                "wow-sidecar-config-seed": {"image": MOD.EXPECTED_IMAGE},
            },
            "configs": {
                "fixture": {"content": MOD.FIXTURE_MARKER},
            },
        }
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/"compose.json").write_text(json.dumps(compose),encoding="utf-8")
            control={
                "schema":MOD.SCHEMA,
                "foundry_ref":"a"*40,
                "secrets_captured":False,
                "candidate":{
                    "wow_image":MOD.EXPECTED_IMAGE,
                    "permissions_helper":MOD.EXPECTED_HELPER,
                },
                "runtime":{
                    "app_name":MOD.EXPECTED_APP_NAME,
                    "production_credentials_present":False,
                    "fixture_key_marker":MOD.FIXTURE_MARKER,
                    "fixture_config_dir":MOD.EXPECTED_CONFIG_DIR,
                    "fixture_state_dir":MOD.EXPECTED_STATE_DIR,
                },
                "artifacts":{"compose_canonical_sha256":MOD.canonical_sha256(compose)},
            }
            (root/"control.json").write_text(json.dumps(control),encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"Foundry source ref drifted"):
                MOD.load_control(root,"b"*40)


if __name__ == "__main__":
    unittest.main()
