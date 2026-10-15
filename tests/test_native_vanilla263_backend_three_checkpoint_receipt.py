"""G4 synthetic JSON adjudication: cannot infer live native world from packets."""
from __future__ import annotations
import copy
import unittest

from scripts.assert_vanilla263_native_t6_receipt import check
from tests.test_native_vanilla263_player_guest_receipt import guest
from scripts.admit_vanilla263_native_t6_control import APP

BLOCKS = {
    "preaction": ["minecraft:air", "minecraft:iron_bars", "minecraft:black_concrete"],
    "candidate": ["minecraft:redstone_block", "minecraft:air", "minecraft:sea_lantern"],
    "rollback": ["minecraft:redstone_block", "minecraft:iron_bars", "minecraft:black_concrete"],
}


def backend_fixture():
    root = guest()
    p = root["foundry_materialization"]
    p["native_backend_world"] = {
        "schema": "supracraft.native-vanilla263-live-backend-region/1",
        "classification": "LIVE_NATIVE_BACKEND_THREE_CHECKPOINTS",
        "same_owned_guest_three_checkpoints": True,
        "backend_independent_world_oracle_pass": True,
        "collage_mutation_authorized": False,
        "physical_true_nas_apply": "HOLD",
        "preparation": {
            "schema": "supracraft.native-vanilla263-mineflayer-causal/1",
            "classification": "FIXED_PLAYER_FIXTURE_PREPARATION_ONLY",
            "stage": "candidate-prep",
            "client_protocol777_connected_and_spawned": True,
            "client_fixture_prepared_without_core_placement": True,
            "native_guest_backend_independent_oracle_qualified": False,
            "collage_mutation_authorized": False,
            "physical_true_nas_apply": "HOLD",
        },
    }
    for i, (stage, block_states) in enumerate(BLOCKS.items()):
        p["native_backend_world"][stage] = {
            "schema": "supracraft.native-vanilla263-server-owned-anvil/1",
            "classification": "LIVE_NATIVE_STOPPED_OWNER_ANVIL_READBACK",
            "stage": stage, "region_sha256": str(i+1)*64,
            "coordinates": [[0,70,0],[2,70,0],[1,70,1]],
            "block_states": block_states, "block_state_expectations_matched": True,
            "requested_native_app": APP,
            "requested_native_world": "rdtepool/minecraft-vanilla-263-t6-world",
            "requested_native_world_file_fixed": True,
            "read_only_middleware_calls": True,
            "live_guest_identity_independently_verified": True,
            "native_guest_server_owned_bytes_proven": True,
            "server_quiescence_proven": True,
            "raw_region_published": False,
            "collage_mutation_authorized": False,
            "physical_true_nas_apply": "HOLD",
            "downloaded_file_size": 12288,
        }
        p["readiness"]["g4-" + stage] = copy.deepcopy(p["readiness"]["reinstall"])
    return root


def admit(root, backend=True):
    return check(root, require_collage=True,
                 require_lantern_staged=True, require_native_rollback=True,
                 require_native_client_visibility=True,
                 require_native_backend_region=backend)


class ThreeCheckpointReceiptTests(unittest.TestCase):
    def test_synthetic_shape_and_falsely_upgraded_015_refused(self):
        admit(backend_fixture())  # mocked JSON validation, NOT live acceptance
        old = guest()
        admit(old, backend=False)  # 015 client-only acceptance preserved
        with self.assertRaises(ValueError):
            admit(old)

    def test_backend_requires_all_prior_gates(self):
        with self.assertRaisesRegex(ValueError, "backend world region requires G2/G3"):
            check(backend_fixture(), require_native_backend_region=True)

    def test_no_forged_guest_identity_or_server_owned_file(self):
        for stage in BLOCKS:
            for field, bad in (
                ("block_states", ["minecraft:redstone_block"]*3),
                ("stage", "rollback" if stage != "rollback" else "candidate"),
                ("region_sha256", "nothex"),
                ("coordinates", [[100,70,0]]),
                ("requested_native_world", "foreign-world"),
                ("requested_native_app", "foreign"),
                ("live_guest_identity_independently_verified", False),
                ("native_guest_server_owned_bytes_proven", False),
                ("server_quiescence_proven", False),
                ("raw_region_published", True),
                ("read_only_middleware_calls", False),
                ("downloaded_file_size", 0),
                ("collage_mutation_authorized", True),
            ):
                with self.subTest(stage=stage, field=field):
                    doc=backend_fixture()
                    doc["foundry_materialization"]["native_backend_world"][stage][field]=bad
                    with self.assertRaises(ValueError):
                        admit(doc)

    def test_replay_and_absent_clean_control_refused(self):
        doc=backend_fixture()
        proof=doc["foundry_materialization"]["native_backend_world"]
        proof["rollback"]["region_sha256"]=proof["candidate"]["region_sha256"]
        with self.assertRaisesRegex(ValueError, "hash replay"):
            admit(doc)
        doc=backend_fixture()
        del doc["foundry_materialization"]["native_backend_world"]["preaction"]
        with self.assertRaises(ValueError): admit(doc)
        doc=backend_fixture()
        del doc["foundry_materialization"]["readiness"]["g4-candidate"]
        with self.assertRaisesRegex(ValueError,"restart/health missing"): admit(doc)

    def test_actor_authority_does_not_inherit_backend_pass(self):
        doc=backend_fixture()
        doc["foundry_materialization"]["native_backend_world"]["physical_true_nas_apply"]="READY"
        with self.assertRaises(ValueError):admit(doc)
        doc=backend_fixture()
        doc["foundry_materialization"]["native_backend_world"]["collage_mutation_authorized"]=True
        with self.assertRaises(ValueError):admit(doc)

    def test_preparation_must_have_no_claimed_backend_proof(self):
        for field, bad in (("stage","rollback"),("client_fixture_prepared_without_core_placement",False),
                           ("native_guest_backend_independent_oracle_qualified", True)):
            doc=backend_fixture()
            doc["foundry_materialization"]["native_backend_world"]["preparation"][field]=bad
            with self.assertRaises(ValueError):admit(doc)


if __name__ == "__main__":
    unittest.main()
