from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse

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

    def test_synthetic_fixture_preflight_sends_no_provider_token(self):
        text = SCRIPT.read_text(encoding="utf-8")
        block = text.split("def preflight_public_fixture", 1)[1].split(
            "def load_bundle", 1
        )[0]
        self.assertIn('method="POST"', block)
        self.assertIn('method="GET"', block)
        self.assertIn("except TimeoutError", block)
        self.assertIn("synthetic metadata hold-open returned before the preflight timeout", block)
        self.assertNotIn("Authorization", block)
        self.assertIn('"ENVIRONMENT_FAILURE"', text)
        self.assertIn('"synthetic_fixture_preflight"', text)

    def test_default_metadata_fixture_holds_open_before_jit_credentials(self):
        self.assertTrue(MOD.DEFAULT_METADATA_URL.startswith("https://httpbin.org/drip?"))
        self.assertIn("delay=60", MOD.DEFAULT_METADATA_URL)
        self.assertIn("path=", MOD.DEFAULT_METADATA_URL)
        expanded = MOD.DEFAULT_METADATA_URL.rstrip("/") + "/credentials/runner"
        parsed = urllib.parse.urlsplit(expanded)
        self.assertEqual(parsed.path, "/drip")
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query.get("path"), ["/credentials/runner"])
        self.assertEqual(query.get("delay"), ["60"])

    def test_expected_app_name_is_bound_before_provider_create_for_cleanup(self):
        text = SCRIPT.read_text(encoding="utf-8")
        bind = text.index('app_name = bundle["expected_app_name"]')
        create = text.index('"CreateInstance", stdin_object=bootstrap')
        self.assertLess(bind, create)

    def test_create_failure_job_capture_is_sanitized_and_excludes_arguments(self):
        token = "g3-secret-synthetic-token"

        class FakeSession:
            def call(self, method, params):
                self.method = method
                self.params = params
                return [
                    {
                        "id": 77,
                        "method": "app.create",
                        "state": "FAILED",
                        "arguments": [{
                            "app_name": "garm-g3-controlle-g3-synthetic-runner",
                            "custom_compose_config": {
                                "services": {
                                    "runner": {
                                        "environment": {
                                            "GARM_INSTANCE_TOKEN": token,
                                        }
                                    }
                                }
                            },
                        }],
                        "error": f"failed with {token}",
                        "exception": f"trace {token}",
                        "progress": {"description": f"cleanup {token}", "percent": 80},
                        "logs_excerpt": f"container stderr {token}",
                        "logs_path": "/var/log/jobs/77.log",
                    }
                ]

        session = FakeSession()
        got = MOD.capture_create_failure_job(
            session, "garm-g3-controlle-g3-synthetic-runner", token
        )
        self.assertEqual(session.method, "core.get_jobs")
        self.assertTrue(got["found"])
        self.assertEqual(got["id"], 77)
        self.assertTrue(got["logs_available"])
        self.assertNotIn("arguments", got)
        self.assertNotIn(token, json.dumps(got, sort_keys=True))
        self.assertIn("<synthetic-token>", got["logs_excerpt"])

    def test_app_lifecycle_excerpt_is_bounded_and_redacts_sensitive_values(self):
        app = "garm-g3-controlle-g3-synthetic-runner"
        token = "g3-sensitive-token"
        api_key = "api-sensitive-value"
        lines = [f"noise-{i}" for i in range(220)]
        lines += [
            f"compose up {app}",
            f"stderr contains {token}",
            f"environment accidentally contains {api_key}",
            "fatal: exact compose failure",
        ]
        got = MOD.select_sanitized_log_excerpt(
            "\n".join(lines), app, [token, api_key], context_lines=3, max_chars=1000
        )
        self.assertTrue(got["app_name_observed"])
        self.assertIn("fatal: exact compose failure", got["excerpt"])
        self.assertNotIn(token, got["excerpt"])
        self.assertNotIn(api_key, got["excerpt"])
        self.assertGreaterEqual(got["line_count"], 224)

    def test_appliance_log_capture_uses_single_specific_filesystem_source(self):
        text = SCRIPT.read_text(encoding="utf-8")
        block = text.split("def capture_app_lifecycle_log", 1)[1].split(
            "def query_app", 1
        )[0]
        self.assertIn('"core.download"', block)
        self.assertIn('"filesystem.get"', block)
        self.assertIn('"/var/log/app_lifecycle.log"', block)
        self.assertIn("ssl.create_default_context", block)
        self.assertNotIn("GITHUB_TOKEN", block)
        self.assertNotIn("TRUENAS_API_KEY", block)

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
