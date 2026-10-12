#!/usr/bin/env python3
"""Cheap falsification of exact Minecraft/TrueNAS source/control semantics."""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "minecraft_t6", ROOT / "scripts/truenas_middleware_minecraft_t6_probe.py"
)
mc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mc)

SOURCE_SHA = "a" * 40


def fixture() -> dict:
    values = {
        "resources": {"limits": {"cpus": 2, "memory": 4096}},
        "minecraft": {
            "type": "PAPER", "version": "1.21.11", "eula": True, "online_mode": True,
            "enable_rcon": False, "seed": None, "additional_envs": [
                {"name": k, "value": v} for k, v in mc.REQUIRED_OWNER.items()
            ],
        },
        "storage": {
            "data": {"type": "ix_volume"},
            "additional_storage": [{
                "type": "host_path", "mount_path": "/data/world",
                "read_only": False,
                "host_path_config": {"path": "/opt/tests/collage-world-only"},
            }],
        },
        "network": {"host_network": False,
                    "server_port": {"port_number": 25565, "bind_mode": "published"}},
    }
    return {
        "schema": mc.SCHEMA,
        "foundry_ref": SOURCE_SHA,
        "target": {
            "truenas_version": "25.04.1",
            "expected_system_version": "TrueNAS-25.04.1",
            "profile_git_blob_sha": mc.EXPECTED_PROFILE,
            "middleware_commit": mc.EXPECTED_MIDDLEWARE,
        },
        "source": {
            "apps_commit": mc.EXPECTED_APPS_COMMIT,
            "app": "community/minecraft",
            "image_reference": mc.EXPECTED_IMAGE_FRAGMENT,
            "library_version": "2.3.4",
            "source_compose_sha256": "1"*64,
            "values_raw_sha256": "2"*64,
        },
        "runtime": {
            "app_name": mc.APP, "catalog_app": "minecraft",
            "train": "community", "catalog_version_candidate": "1.15.29",
            "paper_version": "1.21.11", "required_owned_world_dataset": mc.DATASET,
            "status_oracle": "minecraft-java-status-oracle/v1",
            "values_template": values,
        },
        "evidence": {
            "source_render_pass": True,
            "live_catalog_version_verified": False,
            "live_minecraft_server_qualified": False,
            "world_retention_qualified": False,
            "physical_truenas_qualified": False,
        },
        "secrets_captured": False,
    }


def admit(doc, expected=SOURCE_SHA):
    doc["control_sha256"] = mc.canonical_sha256(doc)
    with tempfile.TemporaryDirectory() as td:
        (pathlib.Path(td) / "control.json").write_text(json.dumps(doc), encoding="utf8")
        return mc.load_control(pathlib.Path(td), expected)


class TestNativeMinecraftControl(unittest.TestCase):
    def test_good_control_lowering_changes_site_bindings_and_omits_null_optional_seed(self):
        control = admit(fixture())
        initial = copy.deepcopy(control["runtime"]["values_template"])
        lowered = mc.runtime_values(control)
        self.assertIn("seed", initial["minecraft"])
        self.assertIsNone(initial["minecraft"]["seed"])
        self.assertNotIn("seed", lowered["minecraft"])
        self.assertIsNone(control["runtime"]["values_template"]["minecraft"]["seed"])
        self.assertEqual(lowered["storage"]["additional_storage"][0]["host_path_config"]["path"], mc.WORLD)
        self.assertEqual(lowered["network"]["server_port"]["port_number"], mc.PORT)
        self.assertEqual(initial["storage"]["additional_storage"][0]["host_path_config"]["path"],
                         "/opt/tests/collage-world-only")
        self.assertEqual(initial["network"]["server_port"]["port_number"], 25565)
        self.assertEqual(mc.WORLD, "/mnt/rdtepool/minecraft-paper-t6-world")
        self.assertIn("@sha256:", mc.EXPECTED_IMAGE_FRAGMENT)
        self.assertEqual(control["source"]["apps_commit"], mc.EXPECTED_APPS_COMMIT)
        self.assertTrue(mc.owned_config(lowered, lowered))

    def test_explicit_non_null_seed_is_not_implicitly_changed(self):
        doc = fixture()
        doc["runtime"]["values_template"]["minecraft"]["seed"] = "43-meaningful-seed"
        lowered = mc.runtime_values(admit(doc))
        self.assertEqual(lowered["minecraft"]["seed"], "43-meaningful-seed")

    def test_unrelated_optional_nulls_do_not_get_stripped(self):
        doc = fixture()
        doc["runtime"]["values_template"]["minecraft"]["motd"] = None
        lowered = mc.runtime_values(admit(doc))
        self.assertIsNone(lowered["minecraft"]["motd"])
        self.assertNotIn("seed", lowered["minecraft"])

    def test_root_requested_shape_uses_same_native_catalog_revision(self):
        harness = (ROOT / "scripts/gha_kvm_truenas_rdte.sh").read_text(encoding="utf-8")
        self.assertIn('"catalog_version_candidate": "1.15.29", "paper_version": "1.21.11"', harness)
        self.assertNotIn('"catalog_version_candidate": "1.15.24"', harness)

    def test_wrong_producer_rejected(self):
        with self.assertRaisesRegex(mc.MinecraftT6Error, "producer identity"):
            admit(fixture(), expected="b"*40)

    def test_invalid_producer_ref_rejected(self):
        with self.assertRaisesRegex(mc.MinecraftT6Error, "not immutable"):
            admit(fixture(), expected="main")

    def test_control_digest_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            doc = fixture()
            doc["control_sha256"] = "f"*64
            (pathlib.Path(td) / "control.json").write_text(json.dumps(doc))
            with self.assertRaisesRegex(mc.MinecraftT6Error, "canonical digest"):
                mc.load_control(pathlib.Path(td), SOURCE_SHA)

    def test_wrong_target_rejected(self):
        doc = fixture()
        doc["target"]["truenas_version"] = "25.10.7"
        with self.assertRaisesRegex(mc.MinecraftT6Error, "target/profile"):
            admit(doc)

    def test_digest_pinned_minecraft_image_required(self):
        doc = fixture()
        doc["source"]["image_reference"] = "ghcr.io/itzg/minecraft-server:latest"
        with self.assertRaisesRegex(mc.MinecraftT6Error, "catalog source"):
            admit(doc)

    def test_live_catalog_version_mismatch_rejected(self):
        doc = fixture()
        doc["runtime"]["catalog_version_candidate"] = "1.15.24"
        with self.assertRaisesRegex(mc.MinecraftT6Error, "product/source"):
            admit(doc)

    def test_wrong_upstream_source_rejected(self):
        doc = fixture()
        doc["source"]["apps_commit"] = "b"*40
        with self.assertRaisesRegex(mc.MinecraftT6Error, "catalog source"):
            admit(doc)

    def test_paper_is_not_vanilla(self):
        doc = fixture()
        doc["runtime"]["paper_version"] = "26.3"
        with self.assertRaisesRegex(mc.MinecraftT6Error, "product/source"):
            admit(doc)

    def test_preclaimed_live_pass_rejected(self):
        doc = fixture()
        doc["evidence"]["live_minecraft_server_qualified"] = True
        with self.assertRaisesRegex(mc.MinecraftT6Error, "promotes runtime"):
            admit(doc)

    def test_base_world_same_storage_rejected(self):
        doc = fixture()
        doc["runtime"]["values_template"]["storage"]["data"]["type"] = "host_path"
        with self.assertRaisesRegex(mc.MinecraftT6Error, "App ixVolume"):
            admit(doc)

    def test_readonly_external_world_rejected(self):
        doc = fixture()
        doc["runtime"]["values_template"]["storage"]["additional_storage"][0]["read_only"] = True
        with self.assertRaisesRegex(mc.MinecraftT6Error, "writable world"):
            admit(doc)

    def test_ownership_drift_rejected(self):
        doc = fixture()
        doc["runtime"]["values_template"]["minecraft"]["additional_envs"][0]["value"] = "false"
        with self.assertRaisesRegex(mc.MinecraftT6Error, "owner metadata"):
            admit(doc)

    def test_foreign_config_not_adopted(self):
        control = admit(fixture())
        values = mc.runtime_values(control)
        self.assertFalse(mc.owned_config({"minecraft": {"type": "PAPER", "version": "1.21.11"}}, values))
        bad = copy.deepcopy(values)
        bad["minecraft"]["additional_envs"] = []
        self.assertFalse(mc.owned_config(bad, values))

    def test_native_server_port_exact_or_documented_default_only(self):
        desired = {"bind_mode": "published", "port_number": mc.PORT}
        self.assertTrue(mc.native_server_port_matches(dict(desired), desired))
        self.assertTrue(mc.native_server_port_matches(dict(desired, host_ips=[]), desired))
        for forbidden in [
            dict(desired, host_ips=["127.0.0.1"]),
            dict(desired, port_number=mc.PORT+1),
            dict(desired, bind_mode="exposed"),
            dict(desired, unknown="bad"),
            {"port_number": mc.PORT, "host_ips": []},
            None, {},
        ]:
            with self.subTest(value=str(forbidden)):
                self.assertFalse(mc.native_server_port_matches(forbidden, desired))
        self.assertFalse(mc.native_server_port_matches(dict(desired, host_ips=[]),
                         dict(desired, host_ips=["0.0.0.0"])))

    def test_native_port_default_preserves_full_ownership_gate(self):
        desired = mc.runtime_values(admit(fixture()))
        got = copy.deepcopy(desired)
        got["network"]["server_port"]["host_ips"] = []
        self.assertTrue(mc.owned_config(got, desired))
        got["network"]["server_port"]["host_ips"] = ["0.0.0.0"]
        self.assertFalse(mc.owned_config(got, desired))
        got["network"]["server_port"]["host_ips"] = []
        got["minecraft"]["additional_envs"].pop()
        self.assertFalse(mc.owned_config(got, desired))

    def test_port_readback_diagnostics_remain_boolean_and_private(self):
        desired = {"bind_mode": "published", "port_number": mc.PORT}
        diag = mc.port_readback_diagnostics(
            dict(desired, host_ips=["192.0.2.8"], secret="redacted"), desired)
        self.assertTrue(diag["port_number"])
        self.assertTrue(diag["bind_mode"])
        self.assertFalse(diag["host_ips_empty_or_absent"])
        self.assertFalse(diag["only_expected_keys"])
        self.assertTrue(all(type(v) is bool for v in diag.values()))
        self.assertNotIn("192.0.2.8", json.dumps(diag))

    def test_live_owner_mismatch_report_contains_only_boolean_witnesses(self):
        wanted = mc.runtime_values(admit(fixture()))
        exact = mc.owner_readback_vector(copy.deepcopy(wanted), wanted)
        self.assertEqual(set(exact), {"minecraft_type", "minecraft_version",
                                       "owner_environment", "additional_storage", "server_port"})
        self.assertTrue(all(exact.values()))
        corrupted = copy.deepcopy(wanted)
        corrupted["storage"]["additional_storage"][0]["host_path_config"]["path"] = "/private/secret-owner-path"
        corrupted["network"]["server_port"]["port_number"] = 9999
        result = mc.owner_readback_vector(corrupted, wanted)
        self.assertFalse(result["additional_storage"])
        self.assertFalse(result["server_port"])
        self.assertTrue(result["minecraft_type"])
        self.assertFalse(mc.owned_config(corrupted, wanted))
        serialized = json.dumps(result)
        self.assertNotIn("private", serialized)
        self.assertNotIn("/mnt/", serialized)
        self.assertTrue(all(isinstance(value, bool) for value in result.values()))
        self.assertTrue(all(not isinstance(value, str) for value in result.values()))

    def test_runtime_image_matches_digest_with_or_without_tag(self):
        ref = mc.EXPECTED_IMAGE_FRAGMENT
        app = {"active_workloads": {"images": [ref]}}
        self.assertEqual(mc.qualified_native_image(app), ref)
        repo, digest = ref.split("@sha256:", 1)
        normalized = repo.rsplit(":", 1)[0] + "@sha256:" + digest
        app = {"active_workloads": {"container_details": [{"image": normalized}]}}
        self.assertEqual(mc.qualified_native_image(app), normalized)
        app = {"active_workloads": {"images": [ref + ".evil"]}}
        self.assertIsNone(mc.qualified_native_image(app))
        app = {"active_workloads": {"images": ["ghcr.io/itzg/minecraft-server:latest"]}}
        self.assertIsNone(mc.qualified_native_image(app))

    def test_job_error_receipt_redacts_secrets_and_bounds_detail(self):
        state = {"state": "FAILED",
                 "error": "AppValidation: host_path invalid; password=my-secret-123; "
                          "TOKEN=supersecret0987; credential=abcd; literal=known-pass"}
        cleaned = mc.safe_job_error(state, "known-pass")
        self.assertEqual(cleaned["job_state"], "FAILED")
        self.assertTrue(cleaned["error_present"])
        for forbidden in ("my-secret-123", "supersecret0987", "abcd", "known-pass"):
            self.assertNotIn(forbidden, cleaned["error_excerpt"])
        self.assertIn("host_path invalid", cleaned["error_excerpt"])
        large = mc.safe_job_error({"state": "FAILED", "error": "x" * 700}, "secret")
        self.assertLessEqual(len(large["error_excerpt"]), 480)

    def test_status_diagnostic_receipt_only_emits_allowed_failure_category(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "status.json"
            variants = [
                ({"schema": "minecraft-java-status-oracle/v1",
                  "classification": "ORACLE_FAILURE", "oracleSatisfied": False,
                  "failure_type": "ConnectionRefusedError",
                  "failure_reason": "transport failure",
                  "sensitive": "192.0.2.20 aPrivateName"}, "transport_failure"),
                ({"schema": "minecraft-java-status-oracle/v1",
                  "classification": "ORACLE_FAILURE", "oracleSatisfied": False,
                  "failure_type": "OracleFailure",
                  "failure_reason": "server version mismatch"}, "version_mismatch"),
                ({"schema": "minecraft-java-status-oracle/v1",
                  "classification": "ORACLE_FAILURE", "oracleSatisfied": False,
                  "failure_reason": "malformed status JSON"}, "invalid_or_truncated_status"),
                ({"schema": "minecraft-java-status-oracle/v1",
                  "classification": "ORACLE_FAILURE", "oracleSatisfied": False,
                  "failure_reason": "ATTACKER_PASSWORD=supersecret"}, "other_oracle_failure"),
                ({"schema": "minecraft-java-status-oracle/v1",
                  "classification": "SUPPORTED", "oracleSatisfied": True}, "status_supported"),
                ({"schema": "invalid", "failure_reason": "transport failure"}, "invalid_receipt"),
            ]
            for row, expected in variants:
                with self.subTest(expected=expected):
                    p.write_text(json.dumps(row))
                    result = mc.classify_java_status_receipt(p)
                    self.assertEqual(result, expected)
                    self.assertNotIn("192.0.2.20", result)
                    self.assertNotIn("supersecret", result)
            p.write_bytes(b"x" * 5000)
            self.assertEqual(mc.classify_java_status_receipt(p), "missing_or_oversized_receipt")
            p.unlink()
            self.assertEqual(mc.classify_java_status_receipt(p), "missing_or_oversized_receipt")
            p.write_text("{broken")
            self.assertEqual(mc.classify_java_status_receipt(p), "unreadable_receipt")

    def test_readiness_source_probes_level_even_when_protocol_fails(self):
        source = (ROOT / "scripts/truenas_middleware_minecraft_t6_probe.py").read_text()
        self.assertIn("level_ever_observed = level_ever_observed or (stat_level() is not None)", source)
        self.assertIn('"status_oracle_ever_satisfied": status_ever_satisfied', source)
        self.assertIn('"middleware_app_query_succeeded" ', source)
        self.assertNotIn('payload["raw_status_json"]', source)

    def test_status_script_must_be_exact_named(self):
        with tempfile.TemporaryDirectory() as td:
            other = pathlib.Path(td) / "anything.py"
            other.write_text("print('ok')", encoding="utf-8")
            with self.assertRaisesRegex(mc.MinecraftT6Error, "oracle file absent"):
                mc.safe_status_oracle(other, 25565, pathlib.Path(td) / "status.json")


if __name__ == "__main__":
    unittest.main()
