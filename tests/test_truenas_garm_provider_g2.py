from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "truenas_middleware_garm_provider_g2_probe.py"
SPEC = importlib.util.spec_from_file_location("garm_provider_g2_probe", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class GarmProviderG2Tests(unittest.TestCase):
    def test_boundary_is_read_adoption_not_runner_creation(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"provider_create_exercised": False',
            '"provider_delete_exercised": False',
            '"github_jit_registration_exercised": False',
            '"physical_truenas_mutation": False',
            '"insecure_skip_verify": False',
            '"GARM_COMMAND": command',
            '"SSL_CERT_FILE": str(ca_path)',
            '"TRUENAS_API_KEY": api_key',
            '"ListInstances"',
            '"GetInstance"',
        ):
            self.assertIn(required, text)
        self.assertNotIn('"GARM_COMMAND": "CreateInstance"', text)
        self.assertNotIn('"GARM_COMMAND": "DeleteInstance"', text)

    def test_fixture_bundle_binds_product_and_producer_sources(self):
        bundle = {
            "schema": MOD.EXPECTED_FIXTURE_SCHEMA,
            "provider_product_source": MOD.EXPECTED_PROVIDER_PRODUCT_SOURCE,
            "producer_source": "a" * 40,
            "controller_id": MOD.EXPECTED_CONTROLLER_ID,
            "pool_id": MOD.EXPECTED_POOL_ID,
            "fixtures": {
                "valid_local": {},
                "valid_foreign": {},
                "managed_drift": {},
            },
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "garm-provider-g2-fixtures.json").write_text(
                json.dumps(bundle), encoding="utf-8"
            )
            loaded = MOD.load_bundle(root, "a" * 40)
            self.assertEqual(
                loaded["provider_product_source"],
                MOD.EXPECTED_PROVIDER_PRODUCT_SOURCE,
            )
            with self.assertRaisesRegex(RuntimeError, "producer source drifted"):
                MOD.load_bundle(root, "b" * 40)

    def test_g2_fixture_download_is_true_nas_job_local(self):
        workflow = (
            ROOT / ".github" / "workflows" / "gha-kvm-system-rdte.yml"
        ).read_text(encoding="utf-8")
        proxmox = workflow.split("  proxmox-9-2:", 1)[1].split(
            "  truenas-26-beta3:", 1
        )[0]
        truenas = workflow.split("  truenas-26-beta3:", 1)[1]
        marker = "Download exact GARM provider G2 fixtures"
        self.assertNotIn(marker, proxmox)
        self.assertIn(marker, truenas)
        self.assertIn("garm-provider-truenas-g2-fixtures", truenas)
        self.assertIn("--g2-fixture-dir", truenas)

    def test_tls_path_is_verified_and_ephemeral(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            "ssl.create_default_context(cafile=str(cafile))",
            "server_hostname=host",
            '"api_key.create"',
            '"certificate.create"',
            '"system.general.update"',
            '"system.general.ui_restart"',
            '"api_key.delete"',
            '"certificate.delete"',
            '"private_key_recorded": False',
            '"api_key_recorded": False',
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
