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


if __name__ == "__main__":
    unittest.main()
