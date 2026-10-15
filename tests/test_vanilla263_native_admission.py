"""Fail-closed source admission tests; never start a guest or ask for APPLY."""
import copy, json, pathlib, sys, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from qualify_vanilla263_native_admission import (
    BLOB, IMAGE, MIDDLEWARE, OWNER, check, sha, Refused
)

def tuple_():
    request=json.loads((ROOT/"config/truenas-vanilla263-native-admission-request.json").read_text())
    registry=json.loads((ROOT/"config/truenas-rdte-targets.json").read_text())
    extra=[{"name":k,"value":v} for k,v in OWNER.items()]
    control={
        "schema":"semper-supra.minecraft-vanilla-263-truenas-t6-control/1",
        "foundry_ref":"a"*40,
        "target":{"truenas_version":"25.04.2.6",
                  "expected_system_version":"TrueNAS-25.04.2.6",
                  "middleware_commit":MIDDLEWARE,
                  "profile_git_blob_sha":BLOB},
        "source":{"apps_commit":"95b0cc78e75fcd4b128f4ef2f8428034d981f7c2",
                  "catalog_app":"community/minecraft",
                  "catalog_version":"1.15.31","image_reference":IMAGE,
                  "source_compose_sha256":"b"*64},
        "runtime":{"minecraft_version":"26.3","minecraft_protocol":777,
                   "java_version":25,"image_selector":"j25_image",
                   "catalog_version_candidate":"1.15.31",
                   "app_name":"rdte-t6-minecraft-vanilla-263",
                   "required_independent_world_dataset":"rdtepool/minecraft-vanilla-263-t6-world",
                   "values_template":{"minecraft":{
                       "version":"26.3","type":"VANILLA","image_selector":"j25_image",
                       "online_mode":True,"enable_rcon":False,
                       "additional_envs":extra},
                       "storage":{"additional_storage":[{
                           "mount_path":"/data/world","type":"host_path","read_only":False,
                           "host_path_config":{"path":"/opt/tests/collage-vanilla-263-world"}}]},
                       "network":{"host_network":False}}},
        "evidence":{"source_render_pass":True,
                    "live_catalog_version_verified":False,
                    "native_guest_created":False,
                    "gameplay_qualified_by_native_guest":False,
                    "external_world_retention_qualified_by_native_guest":False,
                    "collage_managed_deployment_qualified":False,
                    "physical_truenas_qualified":False},
        "operational_selection":False,"physical_truenas_apply":"HOLD",
    }
    control["control_sha256"]=sha(control)
    return request,control,registry


def amend(t,i,path,value):
    t=list(copy.deepcopy(t))
    target=t[i]
    for part in path[:-1]:
        target=target[part]
    target[path[-1]]=value
    if i==1:
        t[1]["control_sha256"]=sha({k:v for k,v in t[1].items() if k!="control_sha256"})
    return tuple(t)


class GuestAdmissionTests(unittest.TestCase):
    def test_accept_exact_synthetic_control_but_do_not_dispatch(self):
        r=check(*tuple_())
        self.assertEqual(r["classification"],"SOURCE_CONTROL_READY_GUEST_NOT_DISPATCHED")
        self.assertEqual(r["consumer_authority_issue"],627)
        self.assertFalse(r["guest_run_requested"])
        self.assertFalse(r["native_app_created"])
        self.assertEqual(r["physical_truenas_apply"],"HOLD")
    def test_reject_old_p2_request_and_wrong_target(self):
        for key,value in (("product","collage-native-paper"),
                          ("version","25.04.1"),
                          ("consumer_authority_issue",625),
                          ("authority_issue",411),
                          ("request_id","tn-25-04-2-6-t6-vanilla-263-p2-005-replay")):
            with self.subTest(key=key),self.assertRaises(Refused):
                check(*amend(tuple_(),0,[key],value))
    def test_reject_control_digest_tampering(self):
        t=list(tuple_());t[1]["control_sha256"]="0"*64
        with self.assertRaisesRegex(Refused,"CANONICAL"):
            check(*t)
    def test_reject_backend_version_image_target_identity(self):
        for path,value in (
            (["runtime","minecraft_version"],"1.21.11"),
            (["runtime","minecraft_protocol"],774),
            (["runtime","java_version"],21),
            (["source","image_reference"],"wrong-image"),
            (["target","profile_git_blob_sha"],"c"*40),
            (["runtime","values_template","minecraft","version"],26.3),
            (["runtime","values_template","minecraft","type"],"PAPER"),
            (["runtime","values_template","network","host_network"],True),
        ):
            with self.subTest(field=path),self.assertRaises(Refused):
                check(*amend(tuple_(),1,path,value))
    def test_reject_forged_guest_qualification_and_physical_apply(self):
        for path,value in (
            (["evidence","native_guest_created"],True),
            (["evidence","physical_truenas_qualified"],True),
            (["physical_truenas_apply"],"APPLY"),
            (["operational_selection"],True),
        ):
            with self.subTest(field=path),self.assertRaises(Refused):
                check(*amend(tuple_(),1,path,value))
    def test_reject_wrong_world_or_owner_identity(self):
        for path,value in (
            (["runtime","values_template","storage","additional_storage"],[]),
            (["runtime","required_independent_world_dataset"],"foreign-world"),
            (["runtime","values_template","minecraft","additional_envs"],[]),
        ):
            with self.subTest(field=path),self.assertRaises(Refused):
                check(*amend(tuple_(),1,path,value))
    def test_reject_wrong_or_missing_target_registry(self):
        t=list(tuple_())
        t[2]["targets"]=[]
        with self.assertRaisesRegex(Refused,"REGISTRY"):
            check(*t)


if __name__=="__main__":
    unittest.main()
