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
            "enable_rcon": False, "additional_envs": [
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
            "library_version": "2.3.4",
            "source_compose_sha256": "1"*64,
            "values_raw_sha256": "2"*64,
        },
        "runtime": {
            "app_name": mc.APP, "catalog_app": "minecraft",
            "train": "community", "catalog_version_candidate": "1.15.24",
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
    def test_good_control_lowering_changes_only_world_and_port(self):
        control = admit(fixture())
        initial = copy.deepcopy(control["runtime"]["values_template"])
        lowered = mc.runtime_values(control)
        self.assertEqual(lowered["storage"]["additional_storage"][0]["host_path_config"]["path"], mc.WORLD)
        self.assertEqual(lowered["network"]["server_port"]["port_number"], mc.PORT)
        self.assertEqual(initial["storage"]["additional_storage"][0]["host_path_config"]["path"],
                         "/opt/tests/collage-world-only")
        self.assertEqual(initial["network"]["server_port"]["port_number"], 25565)
        self.assertEqual(mc.WORLD, "/mnt/rdtepool/minecraft-paper-t6-world")
        self.assertTrue(mc.owned_config(lowered, lowered))

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

    def test_status_script_must_be_exact_named(self):
        with tempfile.TemporaryDirectory() as td:
            other = pathlib.Path(td) / "anything.py"
            other.write_text("print('ok')", encoding="utf-8")
            with self.assertRaisesRegex(mc.MinecraftT6Error, "oracle file absent"):
                mc.safe_status_oracle(other, 25565, pathlib.Path(td) / "status.json")


if __name__ == "__main__":
    unittest.main()
