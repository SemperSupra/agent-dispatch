from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "truenas_middleware_garm_provider_g3_probe.py"
SPEC = importlib.util.spec_from_file_location("garm_provider_g3_probe", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class GarmProviderG3Tests(unittest.TestCase):
    def fixture_bundle(self) -> dict:
        return {
            "schema": MOD.EXPECTED_FIXTURE_SCHEMA,
            "provider_product_source": MOD.EXPECTED_PROVIDER_PRODUCT_SOURCE,
            "producer_source": "a" * 40,
            "controller_id": MOD.EXPECTED_CONTROLLER_ID,
            "pool_id": MOD.EXPECTED_POOL_ID,
            "bootstrap_template": {
                "callback-url": "https://fixture.invalid/status",
                "metadata-url": "https://fixture.invalid/metadata",
                "instance-token": "placeholder",
            },
            "expected_app_name": "garm-g3-controlle-g3-synthetic-runner",
            "expected_compose_template": {
                "services": {
                    "runner": {
                        "environment": {
                            "GARM_CALLBACK_URL": "https://fixture.invalid/status",
                            "GARM_METADATA_URL": "https://fixture.invalid/metadata",
                            "GARM_INSTANCE_TOKEN": "placeholder",
                        }
                    }
                }
            },
            "run_local_substitutions": MOD.EXPECTED_SUBSTITUTIONS,
        }

    def test_fixture_bundle_binds_product_producer_and_substitution_allowlist(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "garm-provider-g3-fixture.json").write_text(
                json.dumps(self.fixture_bundle()), encoding="utf-8"
            )
            loaded = MOD.load_bundle(root, "a" * 40)
            self.assertEqual(
                loaded["provider_product_source"],
                MOD.EXPECTED_PROVIDER_PRODUCT_SOURCE,
            )

            with self.assertRaisesRegex(RuntimeError, "producer source drifted"):
                MOD.load_bundle(root, "b" * 40)

            bad = self.fixture_bundle()
            bad["run_local_substitutions"] = bad["run_local_substitutions"][:-1]
            (root / "garm-provider-g3-fixture.json").write_text(
                json.dumps(bad), encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "substitution allowlist drifted"):
                MOD.load_bundle(root, "a" * 40)

    def test_lower_fixture_changes_only_callback_metadata_and_synthetic_token(self):
        bundle = self.fixture_bundle()
        callback = "https://example.invalid/anything/status"
        metadata = "https://example.invalid/anything/metadata"
        token = "synthetic-token"
        bootstrap, expected = MOD.lower_fixture(bundle, callback, metadata, token)

        self.assertEqual(bootstrap["callback-url"], callback)
        self.assertEqual(bootstrap["metadata-url"], metadata)
        self.assertEqual(bootstrap["instance-token"], token)
        env = expected["services"]["runner"]["environment"]
        self.assertEqual(env["GARM_CALLBACK_URL"], callback)
        self.assertEqual(env["GARM_METADATA_URL"], metadata)
        self.assertEqual(env["GARM_INSTANCE_TOKEN"], token)

        original = self.fixture_bundle()
        self.assertEqual(
            original["bootstrap_template"]["callback-url"],
            "https://fixture.invalid/status",
        )

    def test_boundary_is_create_readback_retire_not_github_execution(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"CreateInstance"',
            '"GetInstance"',
            '"ListInstances"',
            '"DeleteInstance"',
            '"provider_create_exercised": False',
            '"provider_delete_exercised": False',
            '"github_credentials_present": False',
            '"github_jit_registration_exercised": False',
            '"private_repository_execution": False',
            '"physical_truenas_mutation": False',
            '"capacity_promotion": False',
            '"callback_host_gateway": False',
            '"fallback_cleanup_used": fallback_cleanup_used',
            '"provider_delete_succeeded": provider_delete_succeeded',
        ):
            self.assertIn(required, text)
        self.assertNotIn("GITHUB_TOKEN", text)
        self.assertNotIn("GH_TOKEN", text)
        self.assertNotIn("PRIVATE_KEY", text)

    def test_exact_compose_is_compared_before_retirement(self):
        text = SCRIPT.read_text(encoding="utf-8")
        readback = text.index('session.call("app.config", [app_name])')
        compare = text.index("provider-created exact Compose read-back drifted")
        inactive = text.index("ensure_inactive(session, app_name")
        delete = text.index('"DeleteInstance", instance_id=app_name')
        self.assertLess(readback, compare)
        self.assertLess(compare, inactive)
        self.assertLess(inactive, delete)

    def test_transport_reuses_verified_g2_helper_tuple(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("g2.wait_verified_https", text)
        self.assertIn('"SSL_CERT_FILE": str(ca_path)', text)
        self.assertIn('"TRUENAS_API_KEY": api_key', text)
        self.assertIn("g2.EXPECTED_APPLIANCE != EXPECTED_APPLIANCE", text)
        self.assertIn(
            "g2.EXPECTED_PROVIDER_BINARY_SHA256 != EXPECTED_PROVIDER_BINARY_SHA256",
            text,
        )


if __name__ == "__main__":
    unittest.main()
