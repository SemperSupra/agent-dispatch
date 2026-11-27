"""OP4H source and adversarial only; no real native client or KVM admission."""
from __future__ import annotations
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import qualify_native_vanilla263_mineflayer_causal as target


def good(stage):
    return {
        "schema":target.SCHEMA, "classification":"CLIENT_CAUSAL_VISIBILITY",
        "stage":stage,"requested_version":"26.3","negotiated_version":"26.3",
        "protocol":777,"negotiated_protocol":777,
        "offline_mode":True,"synthetic_bot":"SupraCraftProbe",
        "operation":"mineflayer.placeBlock",
        "connected_and_spawned":True,
        "fixture_via_bounded_bot_commands":True,
        "placed":True,"visible_effect_correct":True,
        "expected_datapack_present":stage=="candidate",
        "rcon_used":False,"backend_independent_oracle_qualified":False,
        "true_nas_physical_apply":False,
        "collage_mutation_authorized":False,"in_guest_server_world":False,
    }


class ClientSourceTests(unittest.TestCase):
    def test_candidate_and_rollback_effects_are_separate_and_no_authority(self):
        for stage in ("candidate", "rollback"):
            receipt=target.validate(good(stage),stage)
            self.assertEqual(receipt["classification"],"CLIENT_CAUSAL_VISIBILITY_ONLY")
            self.assertFalse(receipt["native_guest_backend_independent_oracle_qualified"])
            self.assertFalse(receipt["collage_mutation_authorized"])
            self.assertEqual(receipt["physical_true_nas_apply"],"HOLD")
            self.assertEqual(receipt["client_saw_expected_datapack_effect"],
                             stage=="candidate")
            self.assertEqual(receipt["client_saw_expected_no_datapack_effect"],
                             stage=="rollback")

    def test_preaction_stages_only_prepare_client_fixture(self):
        pre=good("candidate-prep")
        pre.update(classification="CLIENT_FIXTURE_PREPARED",
                   operation="mineflayer.chat.fixedFixture",
                   placed=False, expected_datapack_present=True)
        result=target.validate(pre,"candidate-prep")
        self.assertEqual(result["classification"],"FIXED_PLAYER_FIXTURE_PREPARATION_ONLY")
        self.assertTrue(result["client_fixture_prepared_without_core_placement"])
        self.assertFalse(result["native_guest_backend_independent_oracle_qualified"])
        for field,value in (("placed",True),("operation","mineflayer.placeBlock"),
                            ("backend_independent_oracle_qualified",True),
                            ("expected_datapack_present",False),("rcon_used",True)):
            bad=dict(pre, **{field:value})
            with self.subTest(field=field),self.assertRaises(target.Refused):
                target.validate(bad,"candidate-prep")

    def test_forged_success_protocol_bot_gameplay_and_privilege_are_refused(self):
        for field,value in (
            ("classification","SOURCE_ONLY"),("schema","untrusted"),
            ("requested_version","26.2"),("negotiated_version","1.21.11"),
            ("protocol",774),("negotiated_protocol",True),
            ("offline_mode",False),("synthetic_bot","OtherPerson"),
            ("operation","claim_without_packet"),("connected_and_spawned",False),
            ("fixture_via_bounded_bot_commands",False),
            ("placed",False),("visible_effect_correct",False),
            ("expected_datapack_present",False),
            ("rcon_used",True),("backend_independent_oracle_qualified",True),
            ("true_nas_physical_apply",True),
            ("collage_mutation_authorized",True),("in_guest_server_world",True),
        ):
            bad=good("candidate")
            bad[field]=value
            with self.subTest(field=field), self.assertRaises(target.Refused):
                target.validate(bad,"candidate")
        bad=good("candidate")
        bad["reason_code"]="SECRET_OR_FALSE_POSITIVE"
        with self.assertRaises(target.Refused):
            target.validate(bad,"candidate")
        with self.assertRaises(target.Refused):
            target.validate(good("candidate"),"rollback")

    def test_requires_owned_loopback_and_no_preexisting_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            runtime=base/"node_modules"
            runtime.mkdir()
            for bad in (
                "tcp:0.0.0.0:45451-:25580",
                "tcp:127.0.0.1:45451-:25565",
                "tcp:127.0.0.1:22-:25580",
            ):
                with self.subTest(bad=bad),self.assertRaises(Exception):
                    target.run(stage="candidate",forward=bad,
                               state_dir=base,node_path=runtime)
            (base/"native-mineflayer-candidate.json").write_text("{}")
            with self.assertRaisesRegex(target.Refused,"REPLAY_REFUSED"):
                target.run(stage="candidate",
                           forward="tcp:127.0.0.1:45451-:25580",
                           state_dir=base,node_path=runtime)

    def test_runtime_drops_raw_output_and_never_uses_auth_or_network_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); deps=root/"node_modules"; deps.mkdir()
            def fake(cmd,**kwargs):
                self.assertEqual(cmd,["node",str(target.WORKER)])
                env=kwargs["env"]
                self.assertEqual(env["MC_PORT"],"45451")
                self.assertEqual(env["SUPRACRAFT_NATIVE_STAGE"],"rollback")
                self.assertEqual(env["NODE_PATH"],str(deps))
                self.assertNotIn("secret",str(cmd))
                import json
                Path(env["BOT_RESULT_FILE"]).write_text(json.dumps(good("rollback")))
                return subprocess.CompletedProcess(cmd,0,"SHOULD NEVER PUBLISH","SECRET")
            with patch.object(target.subprocess,"run",side_effect=fake):
                result=target.run(stage="rollback",node_path=deps,state_dir=root,
                                  forward="tcp:127.0.0.1:45451-:25580")
            self.assertNotIn("SECRET",str(result))
            self.assertEqual(result["stage"],"rollback")
            self.assertFalse(result["stock_mojang_client_qualified"])

    def test_absent_client_result_or_nonzero_exit_is_never_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); deps=root/"node_modules"; deps.mkdir()
            with patch.object(target.subprocess,"run",return_value=
                              subprocess.CompletedProcess(["node"],1,"secret","trace")):
                with self.assertRaisesRegex(target.Refused,"RUNTIME_REFUSED"):
                    target.run(stage="candidate",node_path=deps,state_dir=root,
                               forward="tcp:127.0.0.1:45451-:25580")


if __name__=="__main__":
    unittest.main()
