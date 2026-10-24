from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "truenas_middleware_garm_provider_g4_probe.py"
SPEC = importlib.util.spec_from_file_location("garm_provider_g4_probe", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class GarmProviderG4Tests(unittest.TestCase):
    def fixture_bundle(self) -> dict:
        def runner(slot: str, name: str) -> dict:
            callback = f"https://fixture.invalid/{slot}/status"
            metadata = f"https://fixture.invalid/{slot}/metadata"
            token = f"{slot}-placeholder"
            return {
                "slot": slot,
                "bootstrap_template": {
                    "callback-url": callback,
                    "metadata-url": metadata,
                    "instance-token": token,
                },
                "expected_app_name": name,
                "expected_compose_template": {
                    "services": {
                        "runner": {
                            "environment": {
                                "GARM_CALLBACK_URL": callback,
                                "GARM_METADATA_URL": metadata,
                                "GARM_INSTANCE_TOKEN": token,
                            }
                        }
                    }
                },
            }

        return {
            "schema": MOD.EXPECTED_FIXTURE_SCHEMA,
            "provider_product_source": MOD.EXPECTED_PROVIDER_PRODUCT_SOURCE,
            "producer_source": "a" * 40,
            "controller_id": MOD.EXPECTED_CONTROLLER_ID,
            "pool_id": MOD.EXPECTED_POOL_ID,
            "runners": [
                runner("alpha", "garm-g4-controlle-g4-synthetic-c43b29d9"),
                runner("beta", "garm-g4-controlle-g4-synthetic-9e19d328"),
            ],
            "runner": {
                "image": MOD.EXPECTED_RUNNER_IMAGE,
                "cpu": MOD.EXPECTED_CPU,
                "memory_bytes": MOD.EXPECTED_MEMORY_BYTES,
            },
            "retirement_orders": [["alpha", "beta"], ["beta", "alpha"]],
            "run_local_substitutions": MOD.EXPECTED_SUBSTITUTIONS,
            "source_oracles": {
                "two_distinct_provider_owned_names": True,
                "fresh_manager_adopts_exact_pair": True,
            },
        }

    def test_bundle_binds_exact_source_pair_and_substitutions(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "garm-provider-g4-fixture.json").write_text(
                json.dumps(self.fixture_bundle()), encoding="utf-8"
            )
            loaded = MOD.load_bundle(root, "a" * 40)
            self.assertEqual(len(loaded["runners"]), 2)
            self.assertNotEqual(
                loaded["runners"][0]["expected_app_name"],
                loaded["runners"][1]["expected_app_name"],
            )

            with self.assertRaisesRegex(RuntimeError, "producer source drifted"):
                MOD.load_bundle(root, "b" * 40)

            bad = self.fixture_bundle()
            bad["run_local_substitutions"] = bad["run_local_substitutions"][:-1]
            (root / "garm-provider-g4-fixture.json").write_text(
                json.dumps(bad), encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "substitution allowlist drifted"):
                MOD.load_bundle(root, "a" * 40)

    def test_lower_runner_changes_only_three_run_local_values(self):
        runner = self.fixture_bundle()["runners"][0]
        callback = "https://example.invalid/alpha/status"
        metadata = "https://example.invalid/alpha/metadata"
        token = "alpha-token"
        bootstrap, expected = MOD.lower_runner(runner, callback, metadata, token)
        self.assertEqual(bootstrap["callback-url"], callback)
        self.assertEqual(bootstrap["metadata-url"], metadata)
        self.assertEqual(bootstrap["instance-token"], token)
        env = expected["services"]["runner"]["environment"]
        self.assertEqual(env["GARM_CALLBACK_URL"], callback)
        self.assertEqual(env["GARM_METADATA_URL"], metadata)
        self.assertEqual(env["GARM_INSTANCE_TOKEN"], token)

    def test_fixture_urls_are_distinct_public_non_github_boundaries(self):
        alpha = MOD.fixture_urls("alpha")
        beta = MOD.fixture_urls("beta")
        self.assertNotEqual(alpha, beta)
        for callback, metadata in (alpha, beta):
            self.assertTrue(callback.startswith("https://httpbin.org/"))
            self.assertTrue(metadata.startswith("https://httpbin.org/drip?"))
            self.assertIn("delay=60", metadata)

    def test_boundary_includes_concurrent_create_reconnect_and_both_retirements(self):
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "ThreadPoolExecutor(max_workers=2)",
            '"CreateInstance"',
            '"GetInstance"',
            '"ListInstances"',
            '"DeleteInstance"',
            "require_active_delete_refusal",
            '("alpha", "beta")',
            '("beta", "alpha")',
            '"fresh_process_get_list_exact_pair": True',
            '"active_delete_refused_without_peer_corruption": True',
            '"retirement_alpha_then_beta": True',
            '"retirement_beta_then_alpha": True',
            '"post_retirement_provider_inventory_empty": True',
        )
        for item in required:
            self.assertIn(item, text)

    def test_public_boundary_and_cleanup_fail_closed(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"github_credentials_present": False',
            '"github_jit_registration_exercised": False',
            '"private_repository_execution": False',
            '"physical_truenas_mutation": False',
            '"capacity_promotion": False',
            '"fallback_cleanup_used": fallback_cleanup_used',
        ):
            self.assertIn(required, text)
        self.assertNotIn("GITHUB_TOKEN", text)
        self.assertNotIn("GH_TOKEN", text)
        self.assertNotIn("PRIVATE_KEY", text)

    def test_resource_observation_uses_exact_compose_and_ix_apps_statfs(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"aggregate_cpu_limit_units": EXPECTED_CPU * 2', text)
        self.assertIn('"aggregate_memory_limit_bytes": EXPECTED_MEMORY_BYTES * 2', text)
        self.assertIn('"filesystem.statfs"', text)
        self.assertIn('IX_APPS_PATH = "/mnt/.ix-apps"', text)
        self.assertIn('"storage_delta_measured": True', text)

    def test_active_delete_refusal_requires_target_remain_present(self):
        class FakeSession:
            pass

        original_invoke = MOD.invoke_provider
        original_query = MOD.g3.query_app
        try:
            class CP:
                returncode = 1
                stdout = ""
                stderr = "active"

            MOD.invoke_provider = lambda *args, **kwargs: CP()
            MOD.g3.query_app = lambda session, name: {"id": name, "state": "RUNNING"}
            MOD.require_active_delete_refusal(
                Path("/provider"),
                Path("/config"),
                "api-key",
                Path("/ca"),
                "garm-alpha",
                ["token"],
                FakeSession(),
            )

            MOD.g3.query_app = lambda session, name: None
            with self.assertRaisesRegex(RuntimeError, "lost the target App"):
                MOD.require_active_delete_refusal(
                    Path("/provider"),
                    Path("/config"),
                    "api-key",
                    Path("/ca"),
                    "garm-alpha",
                    ["token"],
                    FakeSession(),
                )
        finally:
            MOD.invoke_provider = original_invoke
            MOD.g3.query_app = original_query


if __name__ == "__main__":
    unittest.main()
