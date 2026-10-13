#!/usr/bin/env python3
"""Fail-closed read-only admission edge for distinct vanilla 26.3 native guest.

Only evaluates immutable Foundry control and exact public RDTE target registry.
It neither dispatches a workflow nor contacts or mutates TrueNAS.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

SCHEMA="semper-supra.minecraft-vanilla-263-truenas-t6-control/1"
REQUEST="gha-kvm-truenas-run-request/v1"
VERSION="25.04.2.6"
IMAGE=("ghcr.io/itzg/minecraft-server:2026.10.0-java25@sha256:"
       "5a2ab74ae179c11e2dbbce67f307cdcf2c1257b3abb0f654d3a310b3d8ea57da")
APPS="559b9fe85212c800bc6770f152a65211df137a44"
BLOB="631467044411c96a0fe6d361688b99a794f07c80"
MIDDLEWARE="244b717370fe35fb9eefc3096acfbc25f12b57b6"
ISSUE=627
OWNER={"SUPRACRAFT_COLLAGE_MANAGED":"true",
       "SUPRACRAFT_COLLAGE_SCHEMA":"1",
       "SUPRACRAFT_COLLAGE_MANAGER_ID":"manager-rdte",
       "SUPRACRAFT_COLLAGE_FLEET_ID":"rdte",
       "SUPRACRAFT_COLLAGE_SERVICE_ID":"11111111-1111-4111-8111-111111111111",
       "SUPRACRAFT_COLLAGE_WORLD_ID":"lantern-rdte"}


class Refused(RuntimeError):
    pass


def require(ok:bool, code:str):
    if not ok: raise Refused(code)


def sha(doc):
    return hashlib.sha256(json.dumps(doc,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def check(request:dict, control:dict, registry:dict)->dict:
    require(type(request) is dict and type(control) is dict and type(registry) is dict,
            "INVALID_DOCUMENT")
    require(set(request)=={"schema","request_id","version","rung","product",
                           "authority_issue","consumer_authority_issue","purpose"},
            "REQUEST_SHAPE_DRIFT")
    require(request.get("schema")==REQUEST and request.get("version")==VERSION
            and request.get("rung")=="t6" and
            request.get("product")=="minecraft-vanilla-263" and
            request.get("authority_issue")==423 and
            request.get("consumer_authority_issue")==ISSUE and
            isinstance(request.get("purpose"),str) and len(request["purpose"])>=20,
            "WRONG_PRODUCT_TARGET_OR_AUTHORITY")
    ident=request.get("request_id")
    require(type(ident) is str and re.fullmatch("[a-z0-9][a-z0-9-]{9,99}",ident)
            and ident.startswith("tn-25-04-2-6-t6-vanilla-263-")
            and not any(x in ident for x in ("p2-005","paper","replay")),
            "REUSED_OR_AMBIGUOUS_REQUEST_ID")
    require(control.get("schema")==SCHEMA and
            type(control.get("foundry_ref")) is str and
            re.fullmatch("[a-f0-9]{40}",control["foundry_ref"]),
            "FOUNDRY_CONTROL_AUTHORITY_UNVERIFIED")
    c=dict(control)
    stated=c.pop("control_sha256",None)
    require(type(stated) is str and re.fullmatch("[a-f0-9]{64}",stated) and
            stated==sha(c),"FOUNDRY_CONTROL_CANONICAL_SHA_MISMATCH")
    t=control.get("target") or {}
    s=control.get("source") or {}
    runtime=control.get("runtime") or {}
    evidence=control.get("evidence") or {}
    require(t.get("truenas_version")==VERSION and
            t.get("expected_system_version")=="TrueNAS-"+VERSION and
            t.get("middleware_commit")==MIDDLEWARE and
            t.get("profile_git_blob_sha")==BLOB,
            "TRUENAS_TARGET_PROFILE_DRIFT")
    require(s.get("apps_commit")==APPS and
            s.get("catalog_app")=="community/minecraft" and
            s.get("catalog_version")=="1.15.30" and
            s.get("image_reference")==IMAGE and
            type(s.get("source_compose_sha256")) is str and
            re.fullmatch("[a-f0-9]{64}",s["source_compose_sha256"]),
            "UPSTREAM_CATALOG_IMAGE_OR_SOURCE_DRIFT")
    require(runtime.get("minecraft_version")=="26.3" and
            runtime.get("minecraft_protocol")==777 and
            runtime.get("java_version")==25 and
            runtime.get("image_selector")=="j25_image" and
            runtime.get("catalog_version_candidate")=="1.15.30" and
            runtime.get("app_name")=="rdte-t6-minecraft-vanilla-263" and
            runtime.get("required_independent_world_dataset")==
            "rdtepool/minecraft-vanilla-263-t6-world",
            "NATIVE_RUNTIME_OR_WORLD_IDENTITY_DRIFT")
    v=runtime.get("values_template") or {}
    game=v.get("minecraft") or {}
    extra=game.get("additional_envs")
    require(type(extra) is list and len(extra)==len(OWNER) and
            all(type(x) is dict and set(x)=={"name","value"} for x in extra) and
            {x["name"]:x["value"] for x in extra}==OWNER,
            "OWNER_SERVICE_OR_REALM_DRIFT")
    require(game.get("version")=="26.3" and game.get("type")=="VANILLA" and
            game.get("image_selector")=="j25_image" and
            game.get("online_mode") is True and game.get("enable_rcon") is False,
            "NATIVE_APP_VALUES_DRIFT")
    mounts=v.get("storage",{}).get("additional_storage",[])
    require(type(mounts) is list and len(mounts)==1 and
            mounts[0].get("mount_path")=="/data/world" and
            mounts[0].get("type")=="host_path" and
            mounts[0].get("read_only") is False and
            mounts[0].get("host_path_config",{}).get("path")==
            "/opt/tests/collage-vanilla-263-world",
            "EXTERNAL_WORLD_DATASET_DRIFT")
    require(v.get("network",{}).get("host_network") is False,
            "UNSAFE_NETWORK_BOUNDARY")
    require(evidence.get("source_render_pass") is True and
            all(evidence.get(x) is False for x in (
                "live_catalog_version_verified","native_guest_created",
                "gameplay_qualified_by_native_guest",
                "external_world_retention_qualified_by_native_guest",
                "collage_managed_deployment_qualified",
                "physical_truenas_qualified")) and
            control.get("operational_selection") is False and
            control.get("physical_truenas_apply")=="HOLD",
            "UNSUPPORTED_GUEST_OR_PHYSICAL_CLAIM")
    target=next((x for x in registry.get("targets",[]) if type(x) is dict and
                 x.get("version")==VERSION),None)
    require(type(target) is dict and
            target.get("system_version")=="TrueNAS-"+VERSION and
            target.get("middleware_commit")==MIDDLEWARE and
            target.get("foundry_profile_blob")==BLOB and
            target.get("authority_issue")==423 and
            registry.get("policy",{}).get("heavyweight_slot")=="shared-one-at-a-time" and
            registry.get("policy",{}).get("vendor_digest_sidecar_required") is True,
            "PUBLIC_RUNNER_TARGET_REGISTRY_DRIFT")
    return {"schema":"supracraft.minecraft-vanilla263-native-t6-admission/1",
            "classification":"SOURCE_CONTROL_READY_GUEST_NOT_DISPATCHED",
            "request_id":ident,"consumer_authority_issue":ISSUE,
            "target_version":VERSION,"foundry_ref":control["foundry_ref"],
            "control_sha256":stated,"oci_image":IMAGE,
            "native_app_created":False,"guest_run_requested":False,
            "provider_observed":False,"realm_admission_qualified":False,
            "physical_truenas_apply":"HOLD",
            "next_gate":"EXACT_NATIVE_GUEST_CONSUMER_SOURCE_AND_NEW_REQUEST_EDGE"}


def main():
    p=argparse.ArgumentParser()
    for arg in ("request","control","registry","out"):
        p.add_argument("--"+arg,required=True,type=Path)
    a=p.parse_args()
    try:
        ret=check(json.loads(a.request.read_text()),
                  json.loads(a.control.read_text()),
                  json.loads(a.registry.read_text()))
        code=0
    except (ValueError,OSError,Refused,TypeError) as exc:
        ret={"schema":"supracraft.minecraft-vanilla263-native-t6-admission/1",
             "classification":"REFUSED","reason":str(exc)[:150],
             "guest_run_requested":False,"physical_truenas_apply":"HOLD"}
        code=2
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(ret,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"classification":ret["classification"],
                      "reason":ret.get("reason")},sort_keys=True))
    return code


if __name__=="__main__":
    raise SystemExit(main())
