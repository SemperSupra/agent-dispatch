#!/usr/bin/env python3
"""Actual Foundry producer v1 contract checks; source-only, not runtime mocks."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from truenas_foundry_artifact_gate import admit, canonical_sha, ArtifactGateError

TARGET = "25.04.2.6"
SOURCE_REF = "c4fa7cc1287592036866c2510f83b98e047165ac"
TREE = "sha256:" + "1" * 64
PROFILE = ".foundry/truenas-compatibility/25.04.2.6-materialization.json"
IMAGE = "ghcr.io/observed/probe@sha256:" + "a" * 64


def source_shaped_artifact():
    """Mirror actual tools/package_truenas_deployment_artifact.py output keys.

    The independent source check must confirm field compatibility with the
    pinned upstream producer. This fixture never establishes TrueNAS runtime.
    """
    compose = {
        "services": {
            "probe": {
                "image": IMAGE,
                "read_only": True,
                "security_opt": ["no-new-privileges:true"],
            }
        }
    }
    sha = canonical_sha(compose)
    d = {
        "schema": "truenas-foundry-deployment-artifact/v1",
        "runtime_target": "truenas-scale-apps",
        "app_name": "foundry-rdte-probe",
        "compose_sha256": sha,
        "materialization_identity": "sha256:" + sha,
        "required_methods": ["app.query", "app.config", "app.create", "app.update"],
        "create_payload": {
            "custom_app": True,
            "app_name": "foundry-rdte-probe",
            "custom_compose_config": compose,
        },
        "update_payload": {"custom_compose_config": compose},
        "provenance": {
            "source": "foundry-inventory",
            "source_identity": {
                "kind": "foundry-repository",
                "repository": "https://github.com/SemperSupra/truenas-app-foundry.git",
                "ref": SOURCE_REF,
                "path": "fixtures/foundry-rdte-probe",
            },
            "source_tree_sha256": TREE,
            "app_id": "foundry-rdte-probe",
            "target_version": TARGET,
            "target_profile": PROFILE,
            "catalog_validator": "PASS",
            "target_apply_qualified": False,
        },
    }
    d["artifact_sha256"] = canonical_sha(d)
    return d


def reseal(d):
    d["artifact_sha256"] = canonical_sha({k: v for k, v in d.items() if k != "artifact_sha256"})
    return d


def run(doc):
    return admit(doc, target_version=TARGET, source_ref=SOURCE_REF,
                 source_tree_sha256=TREE, profile_path=PROFILE)


class ActualFoundryArtifactTests(unittest.TestCase):
    def test_real_producer_schema_and_exact_source_digest_accepted_without_runtime_claim(self):
        a = run(source_shaped_artifact())
        self.assertEqual(a["classification"], "SOURCE_ADMITTED_NOT_RUN")
        self.assertFalse(a["f0_f5_qualified"])
        self.assertEqual(a["runtime_support_claim"], "OPEN")
        self.assertEqual(a["physical_apply_authority"], "HOLD")
        self.assertFalse(a["independent_live_readback_confirmed"])

    def test_fabricated_jules_adapter_schema_rejected(self):
        bad = {"schema_version": "foundry-rendered-deployment/v1",
               "producer": {"repository": "SemperSupra/truenas-app-foundry"},
               "app": {"compose_config": {"services": {"a": {"image": IMAGE}}}}}
        with self.assertRaisesRegex(ArtifactGateError, "unsupported Foundry deployment"):
            run(bad)

    def test_modified_artifact_digest_refused(self):
        d = source_shaped_artifact()
        d["app_name"] = "foreign-owned"
        with self.assertRaisesRegex(ArtifactGateError, "digest"):
            run(d)

    def test_modified_compose_even_with_resealed_artifact_refused(self):
        d = source_shaped_artifact()
        d["create_payload"]["custom_compose_config"]["services"]["probe"]["command"] = ["sleep", "2"]
        with self.assertRaisesRegex(ArtifactGateError, "Compose payload"):
            run(reseal(d))

    def test_wrong_version_and_profile_refused(self):
        d = source_shaped_artifact()
        with self.assertRaisesRegex(ArtifactGateError, "target/profile"):
            admit(d, target_version="25.10.7", source_ref=SOURCE_REF,
                  source_tree_sha256=TREE, profile_path=PROFILE)
        with self.assertRaisesRegex(ArtifactGateError, "target/profile"):
            admit(d, target_version=TARGET, source_ref=SOURCE_REF,
                  source_tree_sha256=TREE, profile_path="wrong")

    def test_wrong_source_ref_tree_and_validator_refused(self):
        d = source_shaped_artifact()
        with self.assertRaisesRegex(ArtifactGateError, "source revision"):
            admit(d, target_version=TARGET, source_ref="b" * 40,
                  source_tree_sha256=TREE, profile_path=PROFILE)
        with self.assertRaisesRegex(ArtifactGateError, "source tree"):
            admit(d, target_version=TARGET, source_ref=SOURCE_REF,
                  source_tree_sha256="sha256:" + "f" * 64, profile_path=PROFILE)
        d["provenance"]["catalog_validator"] = "PENDING"
        with self.assertRaisesRegex(ArtifactGateError, "validator"):
            run(reseal(d))

    def test_protected_name_not_adopted(self):
        for bad in ("foliorelay", "garm", "system-agent", "production-target"):
            d = source_shaped_artifact()
            d["app_name"] = d["create_payload"]["app_name"] = bad
            with self.assertRaisesRegex(ArtifactGateError, "protected"):
                run(reseal(d))

    def test_mutable_image_or_host_privileged_semantics_refused(self):
        for key, val in (("image", "nginx:latest"), ("privileged", True),
                         ("network_mode", "host"), ("cap_add", ["SYS_ADMIN"])):
            d = source_shaped_artifact()
            d["create_payload"]["custom_compose_config"]["services"]["probe"][key] = val
            d["compose_sha256"] = canonical_sha(d["create_payload"]["custom_compose_config"])
            d["materialization_identity"] = "sha256:" + d["compose_sha256"]
            d["update_payload"] = copy.deepcopy({"custom_compose_config": d["create_payload"]["custom_compose_config"]})
            with self.assertRaises(ArtifactGateError):
                run(reseal(d))

    def test_forged_create_payload_rejected(self):
        d = source_shaped_artifact()
        d["create_payload"] = {"custom_app": True, "app_name": d["app_name"],
                               "custom_app_params": {"compose_file": "{}"}}
        with self.assertRaisesRegex(ArtifactGateError, "normalized Compose"):
            run(reseal(d))

    def test_update_payload_must_match_create(self):
        d = source_shaped_artifact()
        d["update_payload"] = {"custom_compose_config": {"services": {"other": {"image": IMAGE}}}}
        with self.assertRaisesRegex(ArtifactGateError, "update differs"):
            run(reseal(d))


if __name__ == "__main__":
    unittest.main()
