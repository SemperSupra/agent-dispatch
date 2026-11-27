"""Exact, source-bounded *non-executable* Takeout T6 guest control candidate tests."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOC = json.loads((ROOT / "config/takeout-synthetic-guest-control-candidate.json").read_text())
module = importlib.util.spec_from_file_location(
    "takeout_synthetic_fixture", ROOT / "scripts/takeout_synthetic_fixture.py")
fixture = importlib.util.module_from_spec(module)
module.loader.exec_module(fixture)
MANIFEST_DIGEST = "sha256:b182a90bc4f6bfee1c5a39224b6ddd1d1537570cc768d62e6af91a9d09ff98a3"


def validate(doc):
    assert doc["schema"] == "takeout-synthetic-guest-control-candidate/v1"
    assert doc["classification"] == "PRODUCT_NATIVE_GUEST_PLAN_ONLY"
    assert doc["decision"] == "HOLD"
    assert doc["authority"] == {
        "producer": "SemperSupra/agent-dispatch-private#642",
        "foundry": "SemperSupra/truenas-app-foundry-private#327",
        "heavyweight_lane": "SemperSupra/agent-dispatch-private#480",
    }
    assert doc["target"] == {
        "version": "25.04.2.6",
        "middleware_commit": "244b717370fe35fb9eefc3096acfbc25f12b57b6",
        "runner_source": "2376961b4c5d2bb79843046774249cca02dc6888",
        "guest_only": True, "pool": "rdtepool", "pool_data_disks": 2,
    }
    assert doc["source"] == {
        "synthetic_producer_commit": "96f814785217404963e06cbbf75b9a443c7688e8",
        "foundry_template_commit": "70cd8dc02d32dfba1943ff196a4df405945a88d3",
        "upstream_apps_commit": "532236882212e8c5e51d5b49cfe2c6ce3dd5675e",
    }
    image = doc["image"]
    assert image["transport"] == "PUBLIC_GHA_ARTIFACT_GUEST_IMPORT_UNQUALIFIED"
    assert image["artifact_id"] == 11991297351
    assert image["zip_sha256"] == "sha256:293ed237e714aafe6b8f991ae6409005cafc2f89e65da4e6c83fb46afee8869f"
    assert image["oci_manifest_sha256"] == "sha256:32d6d63f5534bac350fcc89dee9b3b03d086ab20d3526e3263fb686193579c8c"
    assert image["docker_image_config_sha256"] == "sha256:de4a72662de5e91d3a72fe4e8b27e984a760150f0df60d492ec547807dcb0ae2"
    assert image["docker_save_gzip_sha256"] == "sha256:8e19aaf612336aae0dd66c34e195e73a37a8035c5e386de3998f787295687687"
    assert image["docker_layers"] == 6
    assert image["tag"] == "takeout-synthetic:local"
    assert image["registry_published"] is False
    assert image["expires_at"] == "2026-10-22T16:42:25Z"
    data = doc["data"]
    assert data["app_name"] == "rdte-t6-takeout-synthetic"
    assert data["archive_dataset"] == "rdtepool/takeout-t6-archives"
    assert data["state_dataset"] == "rdtepool/takeout-t6-state"
    assert data["archive_host_path"] == "/mnt/rdtepool/takeout-t6-archives"
    assert data["state_host_path"] == "/mnt/rdtepool/takeout-t6-state"
    assert data["worker_user"] == "10001:10001"
    assert data["network_mode"] == "none" and data["restart"] == "no"
    assert data["rootfs_read_only"] and not data["external_auto_permissions"]
    assert data["public_ports"] == [] and data["source_fixture_only"]
    complete = doc["completion"]
    assert complete["schema"] == "takeout-application-completion/v1"
    assert complete["scope"] == "synthetic-local-only"
    assert complete["operation_id"] is None
    assert complete["issuer"] == "GUEST_EXECUTOR_APPROVED_FRESH_ONLY"
    assert complete["application_receipt_trusted_alone"] is False
    assert complete["expected_count"] == 4
    assert complete["verification_phase"] == [
        "BEFORE_NATIVE_APP_DELETE", "AFTER_NATIVE_APP_DELETE"]
    assert not complete["process_exit_required"] and not complete["docker_read_required"]
    expected = {name: {"bytes": len(content), "sha256": fixture.sha(content)}
                for name, content in {**fixture.FILES,
                    "retained-sentinel.txt": fixture.SENTINEL}.items()}
    assert complete["expected_manifest"] == expected
    digest = hashlib.sha256(json.dumps(expected, sort_keys=True,
                  separators=(",", ":")).encode()).hexdigest()
    assert complete["expected_manifest_sha256"] == "sha256:" + digest == MANIFEST_DIGEST
    assert all(value is False for name, value in doc["gates"].items()
               if name not in ("source_hosted", "portable_artifact_integrity"))
    assert doc["gates"]["source_hosted"] is True
    assert doc["gates"]["portable_artifact_integrity"] is True
    execution = doc["execution"]
    assert execution == {
        "classification": "HOLD_NO_EXECUTOR",
        "control_artifact_qualified": False,
        "guest_launched": False,
        "physical_trueNAS": False,
        "real_google_data": False,
        "private_github_minutes": False,
        "permission_expansion": False,
        "allow_dispatch": False,
    }
    return {"classification": "EXACT_SOURCE_BOUND_GUEST_CONTROL_PLAN_ONLY",
            "expected_files": len(expected), "manifest_sha256": MANIFEST_DIGEST,
            "image_config_digest": image["docker_image_config_sha256"],
            "native_guest": "NOT_RUN", "physical_apply": "HOLD"}


class GuestControlTests(unittest.TestCase):
    def test_exact_source_bound_control_plan(self):
        result = validate(DOC)
        self.assertEqual(result["expected_files"], 4)

    def test_wrong_archive_digest_rejected(self):
        obj = copy.deepcopy(DOC)
        obj["completion"]["expected_manifest"]["part-003.zip"]["sha256"] = "0" * 64
        with self.assertRaises(AssertionError): validate(obj)

    def test_untrusted_manifest_substitution_rejected(self):
        obj = copy.deepcopy(DOC)
        obj["completion"]["expected_manifest_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(AssertionError): validate(obj)

    def test_foreign_image_rejected(self):
        obj = copy.deepcopy(DOC)
        obj["image"]["docker_image_config_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(AssertionError): validate(obj)

    def test_attempted_dispatch_or_trueNAS_claim_rejected(self):
        for key in ("guest_launched", "allow_dispatch", "physical_trueNAS",
                    "control_artifact_qualified", "permission_expansion", "real_google_data"):
            with self.subTest(key=key):
                obj = copy.deepcopy(DOC)
                obj["execution"][key] = True
                with self.assertRaises(AssertionError): validate(obj)

    def test_docker_read_cannot_be_made_mandatory(self):
        obj = copy.deepcopy(DOC)
        obj["completion"]["docker_read_required"] = True
        with self.assertRaises(AssertionError): validate(obj)

    def test_change_to_host_path_or_public_port_rejected(self):
        for key, value in (("archive_host_path", "/mnt/user-real-pool"),
                           ("public_ports", [443]),
                           ("network_mode", "host")):
            with self.subTest(key=key):
                obj = copy.deepcopy(DOC)
                obj["data"][key] = value
                with self.assertRaises(AssertionError): validate(obj)

    def test_stale_frozen_operation_id_rejected(self):
        obj = copy.deepcopy(DOC)
        obj["completion"]["operation_id"] = "previously-consumed-operation"
        with self.assertRaises(AssertionError): validate(obj)

    def test_replay_of_minecraft_run_request_not_executed(self):
        obj = copy.deepcopy(DOC)
        obj["execution"]["classification"] = "MINECRAFT_RUNNING"
        with self.assertRaises(AssertionError): validate(obj)


if __name__ == "__main__":
    unittest.main()
