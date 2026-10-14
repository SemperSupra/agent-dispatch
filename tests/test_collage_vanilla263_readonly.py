"""P2 new native vanilla product is opt-in; source or Paper guest cannot fake Go/TLS."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from assert_collage_vanilla263_readonly_receipt import check as check_join
from tests.test_truenas_t6_vanilla263_guest import guest_fixture
from truenas_middleware_collage_readback_p2 import NATIVE_VANILLA263_SOURCE
from admit_vanilla263_native_t6_control import APP, OWNER, TARGET


def fixture() -> dict:
    root=guest_fixture()
    root["foundry_materialization"]["collage_readback"]={
        "schema":"semper-supra.collage-native-readback-p2/1",
        "classification":"PROVIDER_READBACK_MATCH",
        "source_sha":NATIVE_VANILLA263_SOURCE,
        "source_plan_sha256":"a"*64,
        "native_app":APP,
        "truenas_version":TARGET,
        "world_id":OWNER["SUPRACRAFT_COLLAGE_WORLD_ID"],
        "service_id":OWNER["SUPRACRAFT_COLLAGE_SERVICE_ID"],
        "ownership_fields_matched":6,
        "tls_cert_sha256":"b"*64,
        "transport":"isolated_guest_tls_verified",
        "credential_scope":"APPS_READ",
        "credential_mutation_phase":"disposable_guest_setup_before_observation",
        "observation_mutation_count":0,
        "real_artifact_sha256_verified":"da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8",
        "native_vanilla263_source_profile":True,
        "world_artifact_format_verified":False,
        "two_rivers_gameplay_qualified":False,
        "world_activated":False,
        "cloudnet_adoption_executed":False,
        "physical_true_nas_mutated":False,
    }
    return root


class TestCollageVanilla263Observer(unittest.TestCase):
    def test_synthetic_join_contract_only_not_live_acceptance(self):
        check_join(fixture())

    def test_native_lifecycle_without_scoped_readback_must_fail_join(self):
        with self.assertRaises(ValueError):
            check_join(guest_fixture())

    def test_real_source_owner_tls_role_mutation_world_scope_negative(self):
        good=fixture()
        updates=[
            ("source_sha","f"*40),
            ("source_plan_sha256","wrong"),
            ("native_app","foreign-app"),
            ("truenas_version","25.04.1"),
            ("world_id","foreign-world"),
            ("service_id","f"*36),
            ("ownership_fields_matched",5),
            ("tls_cert_sha256","not-a-digest"),
            ("transport","insecure"),
            ("credential_scope","FULL_ADMIN"),
            ("observation_mutation_count",1),
            ("credential_mutation_phase","during_observation"),
            ("real_artifact_sha256_verified","c"*64),
            ("native_vanilla263_source_profile",False),
            ("world_artifact_format_verified",True),
            ("world_activated",True),
            ("two_rivers_gameplay_qualified",True),
            ("cloudnet_adoption_executed",True),
            ("physical_true_nas_mutated",True),
        ]
        for key,value in updates:
            r=copy.deepcopy(good)
            r["foundry_materialization"]["collage_readback"][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                check_join(r)
        root=copy.deepcopy(good)
        root["foundry_materialization"]["cleanup"]["zero_residue"]=False
        with self.assertRaises(ValueError):
            check_join(root)

    def test_new_observer_is_separate_product_and_native_legacy_still_valid(self):
        shell=(ROOT/"scripts/gha_kvm_truenas_rdte.sh").read_text()
        yaml=(ROOT/".github/workflows/gha-kvm-system-rdte.yml").read_text()
        self.assertIn('- collage-native-vanilla263',yaml)
        self.assertIn('product == \\'collage-native-vanilla263\\'',yaml)
        self.assertIn('elif [[ "$T6_PRODUCT" == "minecraft-vanilla-263" || "$T6_PRODUCT" == "collage-native-vanilla263" ]]; then',shell)
        self.assertIn('if [[ "$T6_PRODUCT" == "collage-native-vanilla263" ]]; then',shell)
        self.assertIn('COLLAGE_VANILLA_ARGS=()',shell)
        self.assertIn('scripts/assert_collage_vanilla263_readonly_receipt.py',yaml)
        self.assertIn('ref: 17dfacc4351053fa06f8bdbaed7d931c97c1707e',yaml)
        self.assertIn('ref: 4df9fbbfea0ae0e824719db367bd551349a86378',yaml)
        self.assertIn('--native-target-profile vanilla263-250426',yaml)
        self.assertIn('truenas_t6_product == \\'collage-native-vanilla263\\'',yaml)
        self.assertIn('COLLAGE_VANILLA_ARGS',shell)
        self.assertNotIn('TRUENAS_API_KEY',yaml)
        self.assertNotIn('FULL_ADMIN',yaml)


if __name__=="__main__":
    unittest.main()
