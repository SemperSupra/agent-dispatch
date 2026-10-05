#!/usr/bin/env python3
import copy
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
SCRIPT = SCRIPTS / "truenas_middleware_official_catalog_t6_probe.py"
SPEC = importlib.util.spec_from_file_location("official_catalog_t6_probe", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MOD)


def control():
    value = {
        "schema": MOD.EXPECTED_SCHEMA,
        "foundry_ref": MOD.EXPECTED_FOUNDRY_REF,
        "catalog_source": {
            "repository": "https://github.com/truenas/apps.git",
            "commit": MOD.EXPECTED_CATALOG_COMMIT,
        },
        "control": {
            "id": MOD.EXPECTED_CONTROL_ID,
            "role": "universal-candidate-primary",
            "train": "community",
            "catalog_version": MOD.EXPECTED_CATALOG_VERSION,
            "app_version": MOD.EXPECTED_APP_VERSION,
            "lib_version": MOD.EXPECTED_LIB_VERSION,
            "lib_version_hash": MOD.EXPECTED_LIB_VERSION_HASH,
            "source_path": "ix-dev/community/ntfy/app.yaml",
            "source_blob_sha": "187931529f5171bb30f35076e97e16e11cb9fadf",
        },
        "runtime": {
            "app_name": "rdte-t6-catalog-ntfy",
            "create_payload": {
                "custom_app": False,
                "catalog_app": "ntfy",
                "app_name": "rdte-t6-catalog-ntfy",
                "train": "community",
                "version": "1.1.21",
                "values": {"TZ": "Etc/UTC"},
            },
            "config_update_payload": {"values": {"TZ": "Europe/Berlin"}},
            "delete_options": {"remove_images": False, "remove_ix_volumes": False},
            "upgrade": {"not_applicable_requires_receipt": True},
        },
        "target_versions": ["25.04.1", "25.04.2.6", "25.10.7", "26.0.0-BETA.3"],
        "runtime_qualified_targets": [],
        "universal_qualified": False,
        "secrets_captured": False,
    }
    value["control_sha256"] = MOD.canonical_sha256(value)
    return value


def app(c, state="RUNNING", tz=None):
    item = c["control"]
    return {
        "id": c["runtime"]["app_name"],
        "state": state,
        "custom_app": False,
        "version": item["catalog_version"],
        "metadata": {
            "name": item["id"],
            "app_version": item["app_version"],
            "lib_version": item["lib_version"],
            "lib_version_hash": item["lib_version_hash"],
        },
        "active_workloads": {
            "containers": 1,
            "container_details": [{"state": "running", "service_name": "ntfy"}],
        },
    }


class OfficialCatalogT6ContractTests(unittest.TestCase):
    def test_system_version_normalization_matches_control_matrix_tokens(self):
        self.assertEqual(MOD.normalize_system_version("TrueNAS-25.04.1"), "25.04.1")
        self.assertEqual(MOD.normalize_system_version("TrueNAS-25.04.2.6"), "25.04.2.6")
        self.assertEqual(MOD.normalize_system_version("TrueNAS-25.10.7"), "25.10.7")
        self.assertEqual(MOD.normalize_system_version("TrueNAS-26.0.0-BETA.3"), "26.0.0-BETA.3")
        with self.assertRaisesRegex(RuntimeError, "non-empty string"):
            MOD.normalize_system_version(None)

    def test_control_loads_only_exact_native_catalog_identity(self):
        c = control()
        with tempfile.TemporaryDirectory() as td:
            pathlib.Path(td, "control.json").write_text(json.dumps(c), encoding="utf-8")
            got = MOD.load_control(pathlib.Path(td), MOD.EXPECTED_FOUNDRY_REF)
        self.assertEqual(got["control"]["id"], "ntfy")
        self.assertFalse(got["runtime"]["create_payload"]["custom_app"])

    def test_control_rejects_catalog_fingerprint_drift(self):
        c = control()
        c["control"]["lib_version_hash"] = "0" * 64
        unsigned = dict(c)
        unsigned.pop("control_sha256", None)
        c["control_sha256"] = MOD.canonical_sha256(unsigned)
        with tempfile.TemporaryDirectory() as td:
            pathlib.Path(td, "control.json").write_text(json.dumps(c), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "lib_version_hash drifted"):
                MOD.load_control(pathlib.Path(td), MOD.EXPECTED_FOUNDRY_REF)

    def test_plan_is_observe_driven_and_converges_noop(self):
        c = control()
        self.assertEqual(MOD.plan(None, None, c), "CREATE")
        a = app(c)
        self.assertEqual(MOD.plan(a, {"TZ": "Etc/UTC"}, c), "NOOP")
        self.assertEqual(MOD.plan(a, {"TZ": "Europe/Berlin"}, c), "UPDATE")
        self.assertEqual(MOD.plan(a, {"TZ": "Etc/UTC"}, c, desired_running=False), "STOP")
        a["state"] = "STOPPED"
        self.assertEqual(MOD.plan(a, {"TZ": "Etc/UTC"}, c), "START")
        self.assertEqual(MOD.plan(a, {"TZ": "Etc/UTC"}, c, desired_present=False), "DELETE")

    def test_health_allows_completed_permissions_helper(self):
        c = control()
        a = app(c)
        a["active_workloads"] = {
            "containers": 2,
            "container_details": [
                {"state": "running", "service_name": "ntfy"},
                {"state": "exited", "service_name": "permissions"},
            ],
        }
        self.assertTrue(MOD.healthy_running(a, c))
        self.assertTrue(MOD.native_runtime_healthy(a, c, exact_identity=False))

    def test_health_requires_primary_service_running(self):
        c = control()
        a = app(c)
        a["active_workloads"] = {
            "containers": 2,
            "container_details": [
                {"state": "exited", "service_name": "ntfy"},
                {"state": "running", "service_name": "permissions"},
            ],
        }
        self.assertFalse(MOD.healthy_running(a, c))

    def test_health_rejects_missing_primary_service(self):
        c = control()
        a = app(c)
        a["active_workloads"] = {
            "containers": 1,
            "container_details": [{"state": "running", "service_name": "permissions"}],
        }
        self.assertFalse(MOD.healthy_running(a, c))

    def test_foreign_catalog_identity_blocks_mutation(self):
        c = control()
        a = app(c)
        a["metadata"]["lib_version_hash"] = "0" * 64
        self.assertEqual(MOD.plan(a, {"TZ": "Etc/UTC"}, c), "BLOCK_FOREIGN")

    def test_harness_binds_full_native_lifecycle_and_cleanup(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for method in (
            '"app.create"', '"app.update"', '"app.stop"', '"app.start"',
            '"app.redeploy"', '"app.delete"', '"app.upgrade"',
        ):
            self.assertIn(method, text)
        self.assertIn('"NOOP"', text)
        self.assertIn('"NOT_APPLICABLE"', text)
        self.assertIn('"remove_ix_volumes": True', text)
        self.assertNotIn("custom_compose_config", text)

    def test_workflow_and_harness_bind_exact_official_catalog_producer(self):
        workflow = (HERE / ".github" / "workflows" / "gha-kvm-system-rdte.yml").read_text(encoding="utf-8")
        harness = (SCRIPTS / "gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        self.assertIn("export-official-catalog-t6-control.yml@" + MOD.EXPECTED_FOUNDRY_REF, workflow)
        self.assertIn("foundry_ref: " + MOD.EXPECTED_FOUNDRY_REF, workflow)
        self.assertIn("name: official-catalog-truenas-t6-control", workflow)
        self.assertIn("needs.changes.outputs.truenas_t6_product == 'official-catalog'", workflow)
        self.assertIn('foundry_commit="' + MOD.EXPECTED_FOUNDRY_REF + '"', workflow)
        self.assertIn('"official-catalog"', harness)
        self.assertIn("truenas_middleware_official_catalog_t6_probe.py", harness)
        self.assertIn(
            'if [[ "$T6_PRODUCT" != "official-catalog" && "$T6_PRODUCT" != "garm-provider-g5" && "$T6_PRODUCT" != "foliorelay" ]]; then',
            harness,
        )

    def test_probe_requires_observed_methods_and_noop_convergence(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('BOOTSTRAP_METHODS = {"core.get_methods"}', text)
        self.assertIn('call("core.get_methods", [])', text)
        self.assertIn('payload["bootstrap_probes"] = {"core.get_methods": True}', text)
        self.assertIn("REQUIRED_DISCOVERED_METHODS - method_names", text)
        self.assertNotIn('"core.get_methods",\n    "app.query"', text)
        self.assertGreaterEqual(text.count('"NOOP"'), 3)
        self.assertIn('"BLOCK_FOREIGN"', text)
        self.assertIn("refusing adopted official-catalog control state", text)


if __name__ == "__main__":
    unittest.main()
