"""G4 source-only forged native-client visibility receipt negative tests.

Never substitute this JSON unit fixture for live guest + backend + game proof.
"""
from __future__ import annotations
import copy
import unittest

from tests.test_vanilla263_native_rollback_receipt import accepted_fixture
from scripts.assert_vanilla263_native_t6_receipt import check

SCHEMA="supracraft.native-vanilla263-mineflayer-causal/1"


def player(stage):
    return {
        "schema":SCHEMA,
        "classification":"CLIENT_CAUSAL_VISIBILITY_ONLY",
        "stage":stage,
        "client_protocol777_connected_and_spawned":True,
        "offline_synthetic_player_caused_core_placement":True,
        "client_saw_expected_datapack_effect":stage=="candidate",
        "client_saw_expected_no_datapack_effect":stage=="rollback",
        "native_guest_backend_independent_oracle_qualified":False,
        "stock_mojang_client_qualified":False,
        "online_account_qualified":False,
        "collage_mutation_authorized":False,
        "physical_true_nas_apply":"HOLD",
    }


def guest():
    r=accepted_fixture()
    p=r["foundry_materialization"]
    p["native_player_profile"]={
        "schema":"minecraft-vanilla263-disposable-loopback-player/1",
        "classification":"DISPOSABLE_OVERLAY_BOUND",
        "rcon_enabled":False,
        "client_online_account_qualified":False,
        "physical_truenas_apply":"HOLD",
    }
    p["native_player_gameplay"]={
        "same_native_guest_client_causal_visibility":True,
        "backend_independent_world_oracle_pass":False,
        "collage_managed_deployment":False,
        "physical_true_nas_apply":"HOLD",
        "candidate":player("candidate"),
        "rollback":player("rollback"),
    }
    return r


class PlayerGuestReceiptSourceTests(unittest.TestCase):
    def admit(self, row):
        return check(row,require_collage=True,
                     require_lantern_staged=True,require_native_rollback=True,
                     require_native_client_visibility=True)

    def test_synthetic_positive_preserves_false_claims(self):
        self.admit(guest())

    def test_client_cannot_skip_g2_g3(self):
        with self.assertRaisesRegex(ValueError,"native client requires exact G2 and G3"):
            check(guest(),require_collage=True,require_lantern_staged=True,
                  require_native_client_visibility=True)

    def test_missing_and_forged_client_result_refused(self):
        for group,field,bad in (
            ("profile","rcon_enabled",True),
            ("profile","client_online_account_qualified",True),
            ("profile","physical_truenas_apply","APPLY"),
            ("gameplay","same_native_guest_client_causal_visibility",False),
            ("gameplay","backend_independent_world_oracle_pass",True),
            ("gameplay","collage_managed_deployment",True),
            ("client","stage","rollback"),
            ("client","client_protocol777_connected_and_spawned",False),
            ("client","offline_synthetic_player_caused_core_placement",False),
            ("client","client_saw_expected_datapack_effect",False),
            ("client","collage_mutation_authorized",True),
            ("client","online_account_qualified",True),
            ("client","native_guest_backend_independent_oracle_qualified",True),
        ):
            d=guest()
            p=d["foundry_materialization"]
            if group=="profile":p["native_player_profile"][field]=bad
            elif group=="gameplay":p["native_player_gameplay"][field]=bad
            else:p["native_player_gameplay"]["candidate"][field]=bad
            with self.subTest(group=group,field=field):
                with self.assertRaises(ValueError):self.admit(d)
        d=guest()
        del d["foundry_materialization"]["native_player_gameplay"]["rollback"]
        with self.assertRaisesRegex(ValueError,"native offline client causal stage missing"):
            self.admit(d)


if __name__=="__main__":
    unittest.main()
