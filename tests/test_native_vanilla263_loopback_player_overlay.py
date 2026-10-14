"""Exact-source semantics of a disposable offline synthetic player variant.

Static tests intentionally do not claim actual guest isolation or gameplay.
The canonical Foundry signature is independently checked by existing tests;
these tests isolate the additional source-only constrained derivation.
"""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import qualify_native_vanilla263_loopback_player_overlay as overlay

def baseline():
    return {
        "runtime":{"values_template":{
            "minecraft":{
                "online_mode":True,"enable_rcon":False,"rcon_password":"",
                "ops":[],"whitelist":[],"seed":None,
                "additional_envs":[{"name":k,"value":v}
                                   for k,v in overlay.OWNER.items()],
            },
            "network":{"host_network":False,
                       "server_port":{"bind_mode":"published","port_number":25565}},
            "storage":{"additional_storage":[{"mount_path":"/data/world",
                         "host_path_config":{"path":"/opt/tests/collage-vanilla-263-world"}}]},
        }},
    }

def admission():
    return {
        "schema":overlay.PROFILE,
        "rdte_disposable":True,
        "experiment":"offline-mineflayer-player-causal",
        "physical_truenas_apply":"HOLD",
        "operational_selection":False,
        "external_ingress":False,
        "qemu_network":"user",
        "host_forward":overlay.HOST_FORWARD,
        "guest_target":"TrueNAS-"+overlay.TARGET,
        "authorized_bot":"SupraCraftProbe",
    }

def derive(control=None, request=None):
    ctl=control if control is not None else baseline()
    req=request if request is not None else admission()
    with patch.object(overlay,"verify",return_value={"classification":"SOURCE_CONTROL_READY_GUEST_NOT_DISPATCHED"}) as check:
        result=overlay.derive(ctl,req)
        check.assert_called_once_with(ctl)
    return result

class OverlaySourceTests(unittest.TestCase):
    def test_synthetic_player_overlay_preserves_operational_control_and_is_source_only(self):
        before=baseline()
        frozen=copy.deepcopy(before)
        result=derive(before,admission())
        self.assertEqual(before,frozen)
        self.assertEqual(result["classification"],"SOURCE_ONLY_DISPOSABLE_PLAYER_VARIANT")
        self.assertEqual(result["immutable_base_control_sha256"],overlay.CONTROL_SHA)
        minecraft=result["values"]["minecraft"]
        self.assertIs(minecraft["online_mode"],False)
        self.assertEqual(minecraft["ops"],["SupraCraftProbe"])
        self.assertFalse(minecraft["enable_rcon"])
        self.assertEqual(minecraft["rcon_password"],"")
        self.assertFalse(minecraft["whitelist"])
        self.assertNotIn("seed",minecraft)
        self.assertEqual(result["values"]["network"]["server_port"]["port_number"],25580)
        self.assertEqual(result["values"]["storage"]["additional_storage"][0]["host_path_config"]["path"],overlay.WORLD)
        self.assertEqual({x["name"]:x["value"] for x in minecraft["additional_envs"]},overlay.OWNER)
        for field in ("online_account_auth_qualified","in_guest_bot_connected",
                      "datapack_effect_in_native_guest_qualified",
                      "collage_managed_deployment","operational_selection"):
            self.assertIs(result[field],False)
        self.assertEqual(result["physical_truenas_apply"],"HOLD")
        self.assertEqual(len(result["derived_runtime_values_sha256"]),64)

    def test_all_unadmitted_exposure_and_target_variants_refused(self):
        for key,bad in (
            ("rdte_disposable",False),
            ("external_ingress",True),
            ("qemu_network","tap"),
            ("host_forward","tcp:0.0.0.0:25580-:25580"),
            ("host_forward","tcp:127.0.0.1:25580-:25565"),
            ("guest_target","TrueNAS-25.04.1"),
            ("authorized_bot","human-owner"),
            ("physical_truenas_apply","APPLY"),
            ("operational_selection",True),
            ("experiment","live-minecraft"),
        ):
            q=admission()
            q[key]=bad
            with self.subTest(key=key),self.assertRaises(overlay.Refused):
                derive(baseline(),q)
        q=admission()
        q["allow_admin"]=True
        with self.assertRaises(overlay.Refused):
            derive(baseline(),q)

    def test_canonical_baseline_cannot_arrive_already_degraded(self):
        for section,key,bad in (
            ("minecraft","online_mode",False),
            ("minecraft","enable_rcon",True),
            ("minecraft","ops",["OtherUser"]),
            ("minecraft","whitelist",["Anybody"]),
            ("network","host_network",True),
        ):
            c=baseline()
            c["runtime"]["values_template"][section][key]=bad
            with self.subTest(section=section,key=key),self.assertRaises(overlay.Refused):
                derive(c,admission())

    def test_real_canonical_signature_gate_called_not_bypassed(self):
        original=baseline()
        with patch.object(overlay,"verify",side_effect=overlay.Refused("CANONICAL_CONTROL_SHA_DRIFT")):
            with self.assertRaisesRegex(overlay.Refused,"CANONICAL_CONTROL_SHA_DRIFT"):
                overlay.derive(original,admission())

if __name__=="__main__":
    unittest.main()
