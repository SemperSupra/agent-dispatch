#!/usr/bin/env python3
"""Hash-only, no-write successor graph preview from separately qualified WinBot receipt.

The public Agent Dispatch GITHUB_TOKEN must NOT acquire access to a different
repository's product source. This consumes only WinBot's already independently
qualified, bounded metadata; it never requests product bytes from that repo,
creates Git objects, modifies an authorization policy, or launches guests.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import urllib.request

REPO="SemperSupra/agent-dispatch"
BASE_MASTER="2c45ff5e113603fe016982bcc411915f2d6d6d01"
BASE_CONTROL="e7e6b6c4b3a0fd6c31e06f523053d00a623d6fe0"
BASE_POLICY="225dcb07e9d6c322098f629592f86244c8d372d5"
BASE_SOURCE="90d5d8a7244b781c28d438d9ba01155735c765b7"
BASE_PROJECTION="d4120a901d7855a9e0d7bc5f805d5e4b0dad8380abf52322c90f9981094d8b45"
BASE_STAGE="0efa30b3c585a7a5fbee2271040cb8046d7ec262"
BASE_WRAPPER="4891b026c9d45f074080bc2b357052ea595116c8"
# All candidate metadata below is carried from WinBot's already PASSED
# 37888357823 / artifact 11596609077 (ZIP sha256 bdee65da...), and
# Windows PS7 + PS5.1 contract PASS 37888357830.
CANDIDATE_SOURCE="33f047df21269d8556b47f3cda7122ca22ca88ad"
CANDIDATE_STAGE="fea7b9871e8d569f5cd868b85f2f9870249be71c"
CANDIDATE_STAGE_SIZE=47102
CANDIDATE_PROJECTION="270ab93819eb7f0a1c95bdb38f27233af6396bd9cd978aedc47f734ae150deee"
CANDIDATE_PROJECTION_RUN=37888357823
CANDIDATE_PROJECTION_ARTIFACT=11596609077
CANDIDATE_PROJECTION_ZIP_SHA256="bdee65da1773b8c60683d6e96b33155ec70d4389ec250fda8724d7bfd293e2c6"
CANDIDATE_STATIC_RUN=37888357830
STAGE="guest/tools/stage-provision.ps1"
MAX_FILE=524288
MAX_TOTAL=8388608

def blob_sha(raw:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def get(sha:str)->bytes:
    request=urllib.request.Request(
        "https://api.github.com/repos/"+REPO+"/git/blobs/"+sha,
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
                 "Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28"})
    with urllib.request.urlopen(request,timeout=60) as response:
        obj=json.load(response)
    if obj.get("sha")!=sha or obj.get("encoding")!="base64":
        raise ValueError("immutable public graph object missing")
    raw=base64.b64decode(obj["content"])
    if len(raw)!=obj["size"] or blob_sha(raw)!=sha:
        raise ValueError("immutable Git blob content mismatch")
    return raw

def encode(o:dict)->bytes:
    return (json.dumps(o,indent=2)+"\n").encode("utf-8")

def one(s:str,old:str,new:str)->str:
    if s.count(old)!=1:
        raise ValueError("exact A-only control anchor drift")
    return s.replace(old,new,1)

def main()->None:
    master=json.loads(get(BASE_MASTER))
    control=json.loads(get(BASE_CONTROL))
    policy=json.loads(get(BASE_POLICY))
    if (master["source_revision"]!=BASE_SOURCE or
        master["projection_identity_sha256"]!=BASE_PROJECTION or
        master["control_manifest_sha"]!=BASE_CONTROL or
        master["construction"]["stage_provision_blob"]!=BASE_STAGE or
        control["source_revision"]!=BASE_SOURCE or
        control["projection_identity_sha256"]!=BASE_PROJECTION or
        control["stage_provision_blob"]!=BASE_STAGE):
        raise ValueError("parent graph authority drift")
    approved=policy["authorization"]
    if (policy["state"]!="authorized" or
        approved["approved_revision"]!=BASE_SOURCE or
        approved["approved_manifest_sha256"]!=BASE_PROJECTION):
        raise ValueError("parent policy drift")
    if (approved["approved_revision"]==CANDIDATE_SOURCE or
        approved["approved_manifest_sha256"]==CANDIDATE_PROJECTION):
        raise ValueError("unexpected candidate authorization")
    old_batches=[]
    for sha in master["source_batch_manifests"]:
        batch=json.loads(get(sha))
        if batch["source_revision"]!=BASE_SOURCE:
            raise ValueError("parent source batch mismatch")
        old_batches.append(batch)
    old_entries=[entry for b in old_batches for entry in b["entries"]]
    old_paths=[e["path"] for e in old_entries]
    if len(old_paths)!=82 or len(set(old_paths))!=82 or old_paths.count(STAGE)!=1:
        raise ValueError("source path inventory changed")
    original=[e for e in old_entries if e["path"]==STAGE][0]
    if (original["git_blob_sha"]!=BASE_STAGE or
        original["size"]+1524!=CANDIDATE_STAGE_SIZE or
        master["projected_bytes"]!=1053198):
        raise ValueError("source delta size/identity mismatch")
    if CANDIDATE_STAGE_SIZE>MAX_FILE:
        raise ValueError("candidate stage file too large")
    # Hash-only primitive: the reviewed candidate stage bytes deliberately do
    # not enter the Agent Dispatch runner. WinBot upstream qualification is the
    # only authority for the stage SHA and the final source projection SHA256.
    new_batches=[]
    for batch in old_batches:
        b=json.loads(json.dumps(batch))
        b["source_revision"]=CANDIDATE_SOURCE
        for e in b["entries"]:
            if e["path"]==STAGE:
                e["git_blob_sha"]=CANDIDATE_STAGE
                e["size"]=CANDIDATE_STAGE_SIZE
        new_batches.append(b)
    total=master["projected_bytes"]-original["size"]+CANDIDATE_STAGE_SIZE
    if total!=1054722 or total>MAX_TOTAL:
        raise ValueError("candidate source projected size mismatch")
    batch_shas=[blob_sha(encode(b)) for b in new_batches]
    cc=json.loads(json.dumps(control))
    cc["source_revision"]=CANDIDATE_SOURCE
    cc["projection_identity_sha256"]=CANDIDATE_PROJECTION
    cc["stage_provision_blob"]=CANDIDATE_STAGE
    policy_entries=[e for e in cc["entries"] if e["path"]=="rdte/gha/projection-policy.json"]
    if len(policy_entries)!=1 or policy_entries[0]["git_blob_sha"]!=BASE_POLICY:
        raise ValueError("approval policy must be left unchanged and rejecting")
    control_sha=blob_sha(encode(cc))
    mm=json.loads(json.dumps(master))
    mm["source_revision"]=CANDIDATE_SOURCE
    mm["projection_identity_sha256"]=CANDIDATE_PROJECTION
    mm["projected_bytes"]=total
    mm["source_batch_manifests"]=batch_shas
    mm["control_manifest_sha"]=control_sha
    mm["construction"]["stage_provision_blob"]=CANDIDATE_STAGE
    mm["construction"]["source_unchanged"]=False
    mm["construction"]["projection_unchanged"]=False
    mm["construction"]["candidate_requires_authorization"]=True
    mm["construction"]["authorized_for_execution"]=False
    mm["construction"]["source_parent"]=BASE_SOURCE
    mm["construction"]["projection_parent"]=BASE_PROJECTION
    master_sha=blob_sha(encode(mm))
    wrapper=get(BASE_WRAPPER).decode("utf-8-sig")
    for key,old,new in (
        ("MASTER_MANIFEST_SHA",BASE_MASTER,master_sha),
        ("EXPECTED_SOURCE_REVISION",BASE_SOURCE,CANDIDATE_SOURCE),
        ("EXPECTED_PROJECTION_IDENTITY",BASE_PROJECTION,CANDIDATE_PROJECTION),
        ("EXPECTED_CONTROL_MANIFEST_SHA",BASE_CONTROL,control_sha)):
        wrapper=one(wrapper,key+": '"+old+"'",key+": '"+new+"'")
    if wrapper.count(BASE_STAGE)!=2:
        raise ValueError("stage source-pin cardinality changed")
    wrapper=wrapper.replace(BASE_STAGE,CANDIDATE_STAGE)
    wrapper=one(wrapper,"name: WinBot 9.5 Upstream Dependency Windows A-Only",
                "name: WinBot 9.5 Candidate Provision Fix Dormant A-Only")
    wrapper=one(wrapper,"'winbot-95-dependency-a-only-20261009-01'",
                "'winbot-95-candidate-not-admitted'")
    if not all(x in wrapper for x in (
        "agent-dispatch-heavyweight-rdte","queue: max","cancel-in-progress: false")):
        raise ValueError("heavyweight lane invariants changed")
    # Nothing is written into the Git blob store or a triggerable workflow path.
    out={
        "classification":"EXACT_SUCCESSOR_GRAPH_HASH_ONLY_PREVIEW",
        "candidate_product_source_commit":CANDIDATE_SOURCE,
        "candidate_projection_sha256_from_winbot":CANDIDATE_PROJECTION,
        "candidate_stage_git_blob_from_winbot":CANDIDATE_STAGE,
        "changed_projected_paths":[STAGE],
        "projected_file_count":len(old_paths),
        "projected_bytes":total,
        "source_batch_manifest_candidate_shas":batch_shas,
        "control_manifest_candidate_sha":control_sha,
        "master_manifest_candidate_sha":master_sha,
        "dormant_wrapper_candidate_sha":blob_sha(wrapper.encode("utf-8")),
        "exact_upstream_projection_run":CANDIDATE_PROJECTION_RUN,
        "exact_upstream_projection_artifact":CANDIDATE_PROJECTION_ARTIFACT,
        "exact_upstream_projection_artifact_sha256":CANDIDATE_PROJECTION_ZIP_SHA256,
        "exact_upstream_static_qualification_run":CANDIDATE_STATIC_RUN,
        "cross_repo_source_bytes_fetched":False,
        "stage_bytes_verified_in_this_run":False,
        "source_projection_digest_recalculated_in_this_run":False,
        "candidate_metadata_trusted_from_upstream":True,
        "candidate_authorized":False,
        "git_object_writes":False,
        "guest_launched":False,
        "seed_or_terminal_admitted":False,
    }
    p=Path(os.environ["RUNNER_TEMP"])/"winbot-95-successor-graph-preview.json"
    p.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(out,sort_keys=True))
if __name__=="__main__":
    main()
