"""Adversarial vanilla263 T6 guest and legacy-paper isolation source tests."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import truenas_middleware_minecraft_t6_probe as mc
from assert_vanilla263_native_t6_receipt import check as check_guest
import admit_vanilla263_native_t6_control as native


def guest_fixture():
    status={
        "schema":"minecraft-java-status-oracle/v1",
        "classification":"SUPPORTED","oracleSatisfied":True,
        "java_version":"26.3","server_implementation":"vanilla",
        "status_name_contract":"vanilla_exact","server_protocol":777,
        "status_packet_valid":True,"players_counter_valid":True,
    }
    return {
        "contract":"gha-kvm-system-lab/v1",
        "target":{"product":"truenas","version":"25.04.2.6","rung":"T6"},
        "classification":"SUPPORTED","oracleSatisfied":True,
        "phase":"foundry-materialization",
        "source":{"system_version_expected":"TrueNAS-25.04.2.6",
                  "middleware_commit":native.MIDDLEWARE,
                  "foundry_profile_blob":native.PROFILE_BLOB},
        "requested_shape":{"app":{
            "name":native.APP,"catalog_app":"minecraft",
            "catalog_version_candidate":"1.15.30",
            "minecraft_version":"26.3","minecraft_protocol":777}},
        "foundry_materialization":{
            "schema":"truenas-minecraft-vanilla263-t6/v1",
            "classification":"SUPPORTED","oracleSatisfied":True,
            "product":"vanilla-26.3","target":"25.04.2.6",
            "foundry_ref":native.PRODUCER,
            "control_sha256":native.CONTROL_SHA,
            "catalog_version_verified":True,
            "observed_image_reference":native.OCI,
            "image_digest_qualification":"SOURCE_AND_GUEST_REF_MATCH",
            "world_retained_on_delete":True,
            "world_rebound_after_reinstall":True,
            "readiness":{stage:{"protocol":dict(status),
                                "level":{"size":2048}}
                         for stage in ("first","restart","redeploy","reinstall")},
            "cleanup":{"attempted":True,"zero_residue":True,
                       "app_absent":True,"owned_world_dataset_absent":True},
            "secret_values_captured":False,
        },
    }


class TestNativeVanilla263Guest(unittest.TestCase):
    def test_api_key_create_has_bounded_longer_deadline_and_restores_socket(self):
        class Socket:
            def __init__(self): self.value=8.0
            def gettimeout(self): return self.value
            def settimeout(self, value): self.value=value
        class WS:
            def __init__(self): self.sock=Socket()
        ws=WS()
        seen=[]
        def transport(sock, ident, method, params):
            seen.append((ident,method,sock.sock.gettimeout()))
            if method=="api_key.create":
                raise TimeoutError("synthetic secret MUST NOT surface")
            return "ok"
        call=mc.sequenced_guest_ddp_call(
            ws, transport=lambda w, i, m, p:
                mc.scoped_ddp_call(w, i, m, p, transport=transport))
        self.assertEqual(call("app.query", []),"ok")
        with self.assertRaises(TimeoutError):
            call("api_key.create", [{"name":"synthetic-only"}])
        self.assertEqual(ws.sock.gettimeout(),8.0)
        self.assertEqual(call("app.query", []),"ok")
        self.assertEqual([item[0] for item in seen],["1","2","3"])
        self.assertEqual([item[2] for item in seen],
                         [8.0, mc.SCOPED_KEY_CREATE_TIMEOUT_SECONDS, 8.0])
        self.assertEqual(mc.SCOPED_KEY_CREATE_TIMEOUT_SECONDS,60.0)

    def test_scoped_key_success_also_restores_prior_socket_deadline(self):
        class Socket:
            value=11.0
            def gettimeout(self): return self.value
            def settimeout(self,value): self.value=value
        class WS:
            sock=Socket()
        ws=WS()
        observed=[]
        def transport(w, ident, method, params):
            observed.append(w.sock.gettimeout())
            return {"key":"synthetic-test-only"}
        result=mc.scoped_ddp_call(ws,"7","api_key.create",[],
                                  transport=transport)
        self.assertEqual(result,{"key":"synthetic-test-only"})
        self.assertEqual(observed,[60.0])
        self.assertEqual(ws.sock.gettimeout(),11.0)

    def test_full_independent_guest_oracle_fixture(self):
        check_guest(guest_fixture())

    def test_optional_native_collage_readback_requires_independent_tls_and_apps_read(self):
        root=guest_fixture()
        with self.assertRaisesRegex(ValueError,"independent scoped native vanilla readback"):
            check_guest(root,require_collage=True)
        proof={
            "schema":"semper-supra.collage-native-readback-p2/1",
            "classification":"PROVIDER_READBACK_MATCH",
            "source_profile":"vanilla263",
            "source_sha":"2b6abe1141e65b8c6872eeba6c8ae39f5a9635f8",
            "native_app":native.APP, "truenas_version":"25.04.2.6",
            "world_id":"lantern-rdte",
            "service_id":"11111111-1111-4111-8111-111111111111",
            "ownership_fields_matched":6,
            "transport":"isolated_guest_tls_verified",
            "tls_cert_sha256":"a"*64,
            "credential_scope":"APPS_READ",
            "credential_mutation_phase":"disposable_guest_setup_before_observation",
            "observation_mutation_count":0,
            "world_artifact_format_verified":False,
            "world_activated":False,
            "cloudnet_adoption_executed":False,
            "physical_true_nas_mutated":False,
        }
        root["foundry_materialization"]["collage_readback"]=proof
        check_guest(root,require_collage=True)
        for field,bad in (
            ("classification","SOURCE_VALIDATED"),
            ("source_profile","paper"),("source_sha","f"*40),
            ("native_app","rdte-t6-minecraft-paper"),
            ("truenas_version","25.04.1"),
            ("world_id","world-rdte-001"),
            ("ownership_fields_matched",5),
            ("transport","unverified-tls"),
            ("credential_scope","FULL_ADMIN"),
            ("observation_mutation_count",1),
            ("world_activated",True),
            ("tls_cert_sha256","invalid"),
        ):
            with self.subTest(field=field):
                changed=copy.deepcopy(root)
                changed["foundry_materialization"]["collage_readback"][field]=bad
                with self.assertRaises(ValueError):
                    check_guest(changed,require_collage=True)
        # Legacy native guest acceptance remains unchanged by absent readback.
        check_guest(guest_fixture(),require_collage=False)

    def test_optional_real_native_lantern_file_stage_does_not_inherit_gameplay(self):
        root=guest_fixture()
        with self.assertRaisesRegex(ValueError,"actual native Lantern ZIP byte stage"):
            check_guest(root,require_lantern_staged=True)
        hashid="da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8"
        stage={
            "schema":"supracraft.native-vanilla263-lantern-artifact-stage/1",
            "classification":"REAL_NATIVE_GUEST_ARTIFACT_BYTES_STAGED",
            "artifact_sha256":hashid,"download_readback_sha256":hashid,
            "world_id":"lantern-rdte", "native_app":native.APP,
            "native_truenas_version":"25.04.2.6",
            "zfs_world_owned":True,"app_quiesced_before_write":True,
            "persisted_on_restart":True,"persisted_on_reinstall":True,
            "artifact_gameplay_effect_verified":False,
            "collage_managed_deployment":False,
            "principal_authorized_to_apply":False,
            "physical_truenas_apply":"HOLD",
        }
        root["foundry_materialization"]["lantern_artifact_stage"]=stage
        check_guest(root,require_lantern_staged=True)
        for field,bad in (
            ("classification","SOURCE_VALIDATED"),
            ("artifact_sha256","f"*64),
            ("download_readback_sha256","f"*64),
            ("native_app","foreign"),
            ("app_quiesced_before_write",False),
            ("persisted_on_restart",False),
            ("persisted_on_reinstall",False),
            ("artifact_gameplay_effect_verified",True),
            ("collage_managed_deployment",True),
            ("physical_truenas_apply","APPLY"),
        ):
            wrong=copy.deepcopy(root)
            wrong["foundry_materialization"]["lantern_artifact_stage"][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):
                check_guest(wrong,require_lantern_staged=True)
        check_guest(guest_fixture(),require_lantern_staged=False)

    def test_never_promote_paper_legacy_or_source_only(self):
        for change in ("legacy_version","legacy_paper","source_only","wrong_phase"):
            r=guest_fixture()
            if change=="legacy_version":
                r["target"]["version"]="25.04.1"
            if change=="legacy_paper":
                r["foundry_materialization"]["schema"]="truenas-minecraft-paper-t6/v1"
            if change=="source_only":
                r["classification"]="SOURCE_CONTROL_READY_GUEST_NOT_DISPATCHED"
            if change=="wrong_phase":
                r["phase"]="source-admission"
            with self.subTest(change=change),self.assertRaises(ValueError):
                check_guest(r)

    def test_every_phase_real_vanilla_status_and_world_required(self):
        baseline=guest_fixture()
        for phase in ("first","restart","redeploy","reinstall"):
            for field,val in (("java_version","1.21.11"),
                              ("server_implementation","paper"),
                              ("server_protocol",774),
                              ("status_name_contract","paper_brand_exact"),
                              ("status_packet_valid",False),
                              ("players_counter_valid",False)):
                r=copy.deepcopy(baseline)
                r["foundry_materialization"]["readiness"][phase]["protocol"][field]=val
                with self.subTest(phase=phase,field=field),self.assertRaises(ValueError):
                    check_guest(r)
            for size in (0,-1,None):
                r=copy.deepcopy(baseline)
                r["foundry_materialization"]["readiness"][phase]["level"]["size"]=size
                with self.assertRaises(ValueError):
                    check_guest(r)

    def test_identity_integrity_and_cleanup_negative(self):
        for path,val in [
            (("source","middleware_commit"),"f"*40),
            (("requested_shape","app","name"),"foreign"),
            (("foundry_materialization","control_sha256"),"a"*64),
            (("foundry_materialization","observed_image_reference"),"ghcr.io/itzg/minecraft-server:latest"),
            (("foundry_materialization","catalog_version_verified"),False),
            (("foundry_materialization","world_retained_on_delete"),False),
            (("foundry_materialization","world_rebound_after_reinstall"),False),
            (("foundry_materialization","cleanup","zero_residue"),False),
            (("foundry_materialization","cleanup","app_absent"),False),
            (("foundry_materialization","cleanup","owned_world_dataset_absent"),False),
            (("foundry_materialization","secret_values_captured"),True),
        ]:
            r=guest_fixture()
            node=r
            for key in path[:-1]: node=node[key]
            node[path[-1]]=val
            with self.subTest(path=path),self.assertRaises(ValueError):
                check_guest(r)

    def test_00_legacy_paper_profile_remains_exact_default(self):
        self.assertFalse(mc.VANILLA263)
        self.assertEqual(mc.EXPECTED_TARGET,"25.04.1")
        self.assertEqual(mc.MC_VERSION,"1.21.11")
        self.assertEqual(mc.MC_PROTOCOL,774)
        self.assertEqual(mc.APP,"rdte-t6-minecraft-paper")

    def test_explicit_vanilla_profile_is_distinct(self):
        mc.configure_exact_vanilla263()
        self.assertTrue(mc.VANILLA263)
        self.assertEqual(mc.EXPECTED_TARGET,"25.04.2.6")
        self.assertEqual(mc.EXPECTED_PROFILE,native.PROFILE_BLOB)
        self.assertEqual(mc.APP,native.APP)
        self.assertEqual(mc.DATASET,native.WORLD)
        self.assertEqual(mc.EXPECTED_IMAGE_FRAGMENT,native.OCI)
        self.assertEqual(mc.MC_TYPE,"VANILLA")
        self.assertEqual(mc.MC_VERSION,"26.3")
        self.assertEqual(mc.MC_PROTOCOL,777)
        self.assertEqual(mc.CATALOG_PROFILES["1.15.30"]["image"],native.OCI)

    def test_vanilla_status_requires_exact_version_protocol_implementation(self):
        mc.configure_exact_vanilla263()
        with tempfile.TemporaryDirectory() as d:
            script=Path(d)/"minecraft_java_status_oracle.py"
            script.write_text("probe stub, subprocess mocked")
            out=Path(d)/"status.json"
            valid=guest_fixture()["foundry_materialization"]["readiness"]["first"]["protocol"]
            def good(cmd,**kwargs):
                self.assertEqual(cmd[cmd.index("--implementation")+1],"vanilla")
                self.assertEqual(cmd[cmd.index("--expected-protocol")+1],"777")
                self.assertEqual(cmd[cmd.index("--expected-version")+1],"26.3")
                out.write_text(json.dumps(valid))
                return type("Proc",(),{"returncode":0})()
            with patch.object(mc.subprocess,"run",side_effect=good):
                self.assertEqual(mc.safe_status_oracle(
                    script,25580,out,expected_version="26.3",
                    implementation="vanilla",expected_protocol=777)["server_protocol"],777)
            for field,val in (("server_protocol",774),
                              ("server_implementation","paper"),
                              ("java_version","1.21.11")):
                forged=dict(valid,**{field:val})
                def bad(cmd,**kwargs):
                    out.write_text(json.dumps(forged))
                    return type("Proc",(),{"returncode":0})()
                with patch.object(mc.subprocess,"run",side_effect=bad):
                    with self.subTest(field=field),self.assertRaises(mc.MinecraftT6Error):
                        mc.safe_status_oracle(script,25580,out,
                            expected_version="26.3",implementation="vanilla",
                            expected_protocol=777)
            with self.assertRaises(mc.MinecraftT6Error):
                mc.safe_status_oracle(script,25580,out,
                    expected_version="26.3",implementation="paper",expected_protocol=777)

if __name__=="__main__":
    unittest.main()
