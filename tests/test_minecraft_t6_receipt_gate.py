#!/usr/bin/env python3
import copy
import pathlib
import sys
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from assert_minecraft_t6_receipt import check


def supported():
    o={"schema":"minecraft-java-status-oracle/v1","oracleSatisfied":True,
       "java_version":"1.21.11","status_packet_valid":True}
    p={"schema":"truenas-minecraft-paper-t6/v1","classification":"SUPPORTED",
       "oracleSatisfied":True,"control_sha256":"a"*64,"catalog_version_verified":True,
       "world_retained_on_delete":True,"world_rebound_after_reinstall":True,
       "readiness":{k:{"protocol":o,"level":{"size":128}} for k in ("first","restart","redeploy","reinstall")},
       "cleanup":{"zero_residue":True,"app_absent":True,"owned_world_dataset_absent":True}}
    c={"provider":"minecraft-paper-t6","verdict":"SUPPORTED","cleanup_satisfied":True,"provider_receipt":p}
    return {"contract":"gha-kvm-system-lab/v1","classification":"SUPPORTED","oracleSatisfied":True,
            "target":{"product":"truenas","version":"25.04.1","rung":"T6"},
            "session_execution":{"schema":"truenas-session-execution/v1","classification":"SESSION_CLEAN",
                                 "session_clean":True,"capsules":[c]},
            "foundry_materialization":copy.deepcopy(p)}


class GateTests(unittest.TestCase):
    def test_accepts_complete_synthetic(self):
        check(supported())

    def test_workflow_checks_exact_guest_receipt(self):
        y=(ROOT/".github/workflows/gha-kvm-system-rdte.yml").read_text()
        self.assertIn("python3 scripts/assert_minecraft_t6_receipt.py --receipt",y)

    def test_no_green_laundering(self):
        for mutation in (
            lambda x:x.update({"classification":"HARNESS_FAILURE"}),
            lambda x:x.update({"oracleSatisfied":False}),
            lambda x:x.update({"session_execution":None}),
            lambda x:x["session_execution"]["capsules"][0].update({"verdict":"ORACLE_FAILURE"}),
            lambda x:x["session_execution"]["capsules"][0]["provider_receipt"].update({"catalog_version_verified":False}),
            lambda x:x["session_execution"]["capsules"][0]["provider_receipt"].update({"world_rebound_after_reinstall":False}),
            lambda x:x["session_execution"]["capsules"][0]["provider_receipt"]["cleanup"].update({"zero_residue":False}),
            lambda x:x["session_execution"]["capsules"][0]["provider_receipt"]["readiness"].pop("reinstall"),
            lambda x:x.update({"foundry_materialization":None}),
        ):
            d=supported()
            mutation(d)
            with self.assertRaises(ValueError):
                check(d)


if __name__ == "__main__":
    unittest.main()
