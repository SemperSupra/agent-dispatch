"""OP4G independent receipt gate: cannot upgrade staged ZIP/G2 to G3 mechanics."""
from __future__ import annotations
import copy
import unittest
from tests.test_truenas_t6_vanilla263_guest import guest_fixture
from scripts.assert_vanilla263_native_t6_receipt import check
from scripts.admit_vanilla263_native_t6_control import APP

SHA="da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8"

def accepted_fixture():
    root=guest_fixture()
    p=root["foundry_materialization"]
    p["collage_readback"]={
        "schema":"semper-supra.collage-native-readback-p2/1",
        "classification":"PROVIDER_READBACK_MATCH",
        "source_profile":"vanilla263",
        "source_sha":"5ce9ed7c1be814318b435517191622903146cdca",
        "native_app":APP,"truenas_version":"25.04.2.6",
        "world_id":"lantern-rdte",
        "service_id":"11111111-1111-4111-8111-111111111111",
        "ownership_fields_matched":6,"transport":"isolated_guest_tls_verified",
        "credential_scope":"APPS_READ",
        "credential_mutation_phase":"disposable_guest_setup_before_observation",
        "observation_mutation_count":0,"world_artifact_format_verified":False,
        "world_activated":False,"cloudnet_adoption_executed":False,
        "physical_true_nas_mutated":False,"tls_cert_sha256":"a"*64,
    }
    p["lantern_artifact_stage"]={
        "schema":"supracraft.native-vanilla263-lantern-artifact-stage/1",
        "classification":"REAL_NATIVE_GUEST_ARTIFACT_BYTES_STAGED",
        "artifact_sha256":SHA,"download_readback_sha256":SHA,
        "world_id":"lantern-rdte","native_app":APP,
        "native_truenas_version":"25.04.2.6","zfs_world_owned":True,
        "app_quiesced_before_write":True,"persisted_on_restart":True,
        "persisted_on_reinstall":True,
        "artifact_gameplay_effect_verified":False,
        "collage_managed_deployment":False,
        "principal_authorized_to_apply":False,"physical_truenas_apply":"HOLD",
    }
    p["native_world_rollback"]={
        "schema":"supracraft.native-vanilla263-rdte-rollback-mechanics/1",
        "classification":"G3_DISPOSABLE_MECHANICS_ONLY",
        "phase":"injected_fault_rolled_back",
        "snapshot_owned":True,"snapshot_id_verified":True,
        "candidate_present_before_stage":False,
        "release_fault_injected":True,
        "candidate_absent_after_rollback":True,
        "native_app_running_after_rollback":True,
        "native_game_status_rechecked":True,
        "candidate_sha256":SHA,"collage_managed_deployment":False,
        "world_activation_authorized_by_collage":False,
        "actual_player_gameplay_verified":False,
        "physical_true_nas_mutated":False,
    }
    p["readiness"]["g3-rollback"]=copy.deepcopy(p["readiness"]["reinstall"])
    return root


class NegativeReceiptTests(unittest.TestCase):
    def test_source_fixture_positive_and_missing_rollback_refused(self):
        root=accepted_fixture()
        check(root,require_collage=True,require_lantern_staged=True,
              require_native_rollback=True)
        del root["foundry_materialization"]["native_world_rollback"]
        with self.assertRaisesRegex(ValueError,"native disposable rollback receipt missing"):
            check(root,require_collage=True,require_lantern_staged=True,
                  require_native_rollback=True)

    def test_cannot_promote_without_g2_or_real_artifact(self):
        root=accepted_fixture()
        for collage,stage in ((False,False),(True,False),(False,True)):
            with self.subTest(collage=collage,stage=stage):
                with self.assertRaisesRegex(ValueError,"native rollback requires"):
                    check(root,require_collage=collage,
                          require_lantern_staged=stage,require_native_rollback=True)

    def test_forged_cleanup_owner_replay_game_health_and_promotion_are_refused(self):
        for parent,field,value in (
            ("native_world_rollback","snapshot_owned",False),
            ("native_world_rollback","candidate_sha256","f"*64),
            ("native_world_rollback","candidate_absent_after_rollback",False),
            ("native_world_rollback","world_activation_authorized_by_collage",True),
            ("native_world_rollback","collage_managed_deployment",True),
            ("native_world_rollback","actual_player_gameplay_verified",True),
            ("native_world_rollback","physical_true_nas_mutated",True),
            ("native_world_rollback","native_app_running_after_rollback",False),
            ("readiness","g3-rollback",{}),
        ):
            root=accepted_fixture()
            p=root["foundry_materialization"]
            if parent=="readiness":
                p[parent][field]=value
            else:
                p[parent][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                check(root,require_collage=True,
                      require_lantern_staged=True,require_native_rollback=True)


if __name__=="__main__":
    unittest.main()
