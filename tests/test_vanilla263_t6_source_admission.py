"""Native vanilla26.3 admission red/blue tests with exact Foundry producer fixtures."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import admit_vanilla263_native_t6_control as consumer

FOUNDRY=ROOT/".deps"/"vanilla-foundry"
EXPORT=FOUNDRY/"tools"/"export_minecraft_vanilla_263_11533_t6_control.py"


def producer():
    if not EXPORT.is_file():
        raise AssertionError("EXACT_FOUNDRY_PRODUCER_NOT_CHECKED_OUT")
    spec=importlib.util.spec_from_file_location("foundry_vanilla263_exact", EXPORT)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_document():
    f=producer()
    import yaml
    pin=json.loads(f.PIN.read_text())
    values=yaml.safe_load(f.VALUES.read_text())
    profile=json.loads(f.PROFILE.read_text())
    evidence={
        "result":"PASS","truenas_target":"25.04.2.6",
        "runtime_qualification":False,
        "upstream":{"ref":f.SOURCE,"app":"community/minecraft"},
        "server":{"catalog_version":"1.15.33","type":"VANILLA",
                  "minecraft_version":"26.3","image_selector":"j25_image",
                  "image_ref":f.IMAGE,"ownership_metadata":f.IDENTITY,
                  "world_mount":{"source":"/opt/tests/collage-vanilla-263-world"}},
        "compose_sha256":"a"*64,
    }
    return f.produce(consumer.PRODUCER,evidence,pin,values,profile,f.BLOB)


def readmit_local_fixture(doc):
    # Fixture canonical hash differs from real rendered upstream compose hash.
    # Relax only test EXPECTED digest while keeping every semantic gate exact.
    source=copy.deepcopy(doc)
    digest=source.pop("control_sha256")
    assert digest==consumer.canonical_hash(source)
    with patch.object(consumer,"CONTROL_SHA",digest):
        return consumer.verify(doc,expected_digest=digest)


class TestNativeVanilla263SourceAdmission(unittest.TestCase):
    def test_signed_source_is_not_a_guest(self):
        row=readmit_local_fixture(source_document())
        self.assertEqual(row["classification"],
                         "SOURCE_CONTROL_READY_GUEST_NOT_DISPATCHED")
        self.assertEqual(row["minecraft_protocol"],777)
        self.assertFalse(row["native_guest_qualified"])
        self.assertEqual(row["physical_truenas_apply"],"HOLD")

    def test_real_rendered_control_from_exact_producer(self):
        loc=os.environ.get("VANILLA263_SOURCE_CONTROL")
        if not loc:
            self.fail("VANILLA263_SOURCE_CONTROL_MISSING")
        c=json.loads(Path(loc).read_text())
        got=consumer.verify(c)
        self.assertEqual(got["control_sha256"],consumer.CONTROL_SHA)
        self.assertEqual(got["foundry_ref"],consumer.PRODUCER)

    def test_signed_digest_forgery_fails_closed(self):
        c=source_document()
        original_digest=c["control_sha256"]
        c["source"]["image_reference"]="ghcr.io/example:latest"
        # Exercise the production signature check, not the fixture helper's
        # self-consistency assertion. Semantic checks come only after signing.
        with patch.object(consumer,"CONTROL_SHA",original_digest):
            with self.assertRaisesRegex(consumer.Refused,"CANONICAL_CONTROL_SHA_DRIFT"):
                consumer.verify(c,expected_digest=original_digest)
        with self.assertRaisesRegex(consumer.Refused,"CANONICAL_CONTROL_SHA_DRIFT"):
            consumer.verify(c)

    def test_precise_fail_closed_target_runtime_owner_world(self):
        mutations=[
            (("target","truenas_version"),"25.04.1","NATIVE_GUEST_TARGET_DRIFT"),
            (("target","middleware_commit"),"f"*40,"NATIVE_GUEST_TARGET_DRIFT"),
            (("source","apps_commit"),"f"*40,"NATIVE_CATALOG_SOURCE_DRIFT"),
            (("source","catalog_version"),"1.15.29","NATIVE_CATALOG_SOURCE_DRIFT"),
            (("source","image_reference"),"ghcr.io/example:latest","NATIVE_CATALOG_SOURCE_DRIFT"),
            (("runtime","minecraft_version"),"1.21.11","NATIVE_VANILLA_PRODUCT_DRIFT"),
            (("runtime","minecraft_protocol"),774,"NATIVE_VANILLA_PRODUCT_DRIFT"),
            (("runtime","java_version"),21,"NATIVE_VANILLA_PRODUCT_DRIFT"),
            (("runtime","values_template","minecraft","type"),"PAPER","NATIVE_VANILLA_RUNTIME_INPUT_DRIFT"),
            (("runtime","values_template","minecraft","online_mode"),False,"NATIVE_VANILLA_RUNTIME_INPUT_DRIFT"),
            (("runtime","values_template","minecraft","enable_rcon"),True,"NATIVE_VANILLA_RUNTIME_INPUT_DRIFT"),
            (("runtime","values_template","storage","data","type"),"host_path","NATIVE_WORLD_OWNER_BOUNDARY_DRIFT"),
            (("runtime","values_template","storage","additional_storage"),[],"NATIVE_WORLD_OWNER_BOUNDARY_DRIFT"),
            (("runtime","values_template","network","host_network"),True,"NATIVE_PORT_POLICY_DRIFT"),
            (("evidence","native_guest_created"),True,"SOURCE_ONLY_GUEST_OR_PHYSICAL_PROMOTION_DRIFT"),
            (("physical_truenas_apply",),"READY","SOURCE_ONLY_GUEST_OR_PHYSICAL_PROMOTION_DRIFT"),
        ]
        for path,value,refusal in mutations:
            with self.subTest(path=path):
                doc=source_document()
                node=doc
                for key in path[:-1]:
                    node=node[key]
                node[path[-1]]=value
                sign=dict(doc)
                sign.pop("control_sha256")
                doc["control_sha256"]=consumer.canonical_hash(sign)
                with self.assertRaisesRegex(consumer.Refused,refusal):
                    readmit_local_fixture(doc)

    def test_owner_env_duplicate_and_foreign_mount_refused(self):
        for change in ("duplicate_env","foreign_world","readonly_world"):
            with self.subTest(change=change):
                doc=source_document()
                values=doc["runtime"]["values_template"]
                if change=="duplicate_env":
                    values["minecraft"]["additional_envs"].append(
                        dict(values["minecraft"]["additional_envs"][0]))
                elif change=="foreign_world":
                    values["storage"]["additional_storage"][0]["host_path_config"]["path"]="/tmp/foreign"
                else:
                    values["storage"]["additional_storage"][0]["read_only"]=True
                sign=dict(doc)
                sign.pop("control_sha256")
                doc["control_sha256"]=consumer.canonical_hash(sign)
                with self.assertRaises(consumer.Refused):
                    readmit_local_fixture(doc)

    def test_source_only_control_does_not_dispatch_heavy_guest(self):
        # Source qualification has no actuator, even once an independently
        # admitted request-edge legitimately selects vanilla263 for a guest.
        proposed=json.loads((ROOT/"config/truenas-vanilla263-native-admission-request.json").read_text())
        self.assertEqual(proposed["version"],"25.04.2.6")
        self.assertEqual(proposed["product"],"minecraft-vanilla-263")
        self.assertEqual(proposed["consumer_authority_issue"],627)
        self.assertIn("NOT wired",proposed["purpose"])
        workflow=(ROOT/".github/workflows/vanilla263-t6-source-admission.yml").read_text()
        self.assertIn("scripts/admit_vanilla263_native_t6_control.py",workflow)
        self.assertIn("SOURCE_CONTROL_READY_GUEST_NOT_DISPATCHED",workflow)
        self.assertNotIn("gha_kvm_truenas_rdte.sh",workflow)
        self.assertNotIn("--t6-product",workflow)
        self.assertNotIn("config/truenas-rdte-run-request.json",workflow)
        self.assertNotIn("native_guest_qualified\"] is True",workflow)


if __name__=="__main__":
    unittest.main()
