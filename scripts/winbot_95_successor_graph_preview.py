#!/usr/bin/env python3
"""Read-only preflight of the *unapproved* WinBot 9.5 source/graph successor.

Fetches already-authorized public-safe 82-file projection plus the candidate
stage file from WinBot, validates the single-file delta and deterministically
derives the successor batch/control/master/wrapper identities IN MEMORY.
NO git object writes, policy edits, guest launches or source-bearing artifacts.
"""
from __future__ import annotations
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import urllib.request

EXEC_REPO="SemperSupra/agent-dispatch"
PRODUCT_REPO="mark-e-deyoung/WinBot"
BASE_MASTER="2c45ff5e113603fe016982bcc411915f2d6d6d01"
BASE_CONTROL="e7e6b6c4b3a0fd6c31e06f523053d00a623d6fe0"
BASE_POLICY="225dcb07e9d6c322098f629592f86244c8d372d5"
BASE_SOURCE="90d5d8a7244b781c28d438d9ba01155735c765b7"
BASE_PROJECTION="d4120a901d7855a9e0d7bc5f805d5e4b0dad8380abf52322c90f9981094d8b45"
BASE_STAGE="0efa30b3c585a7a5fbee2271040cb8046d7ec262"
CANDIDATE_SOURCE="33f047df21269d8556b47f3cda7122ca22ca88ad"
CANDIDATE_STAGE="fea7b9871e8d569f5cd868b85f2f9870249be71c"
CANDIDATE_PROJECTION="270ab93819eb7f0a1c95bdb38f27233af6396bd9cd978aedc47f734ae150deee"
BASE_WRAPPER="4891b026c9d45f074080bc2b357052ea595116c8"
STAGE="guest/tools/stage-provision.ps1"
MAX_FILE=524288
MAX_TOTAL=8388608

def blob_sha(raw:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def fetch(repo:str,sha:str)->bytes:
    req=urllib.request.Request(
        "https://api.github.com/repos/"+repo+"/git/blobs/"+sha,
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
                 "Accept":"application/vnd.github+json",
                 "X-GitHub-Api-Version":"2022-11-28"})
    with urllib.request.urlopen(req, timeout=60) as f:
        o=json.load(f)
    if o.get("sha")!=sha or o.get("encoding")!="base64":
        raise ValueError("upstream Git blob identity/encoding mismatch")
    raw=base64.b64decode(o["content"])
    if len(raw)!=o["size"] or blob_sha(raw)!=sha:
        raise ValueError("upstream Git blob content mismatch")
    return raw
def encode(v)->bytes:
    return (json.dumps(v,indent=2)+"\n").encode("utf-8")
def replacement_once(s:str,before:str,after:str)->str:
    if s.count(before)!=1:
        raise ValueError("successor control anchor cardinality mismatch")
    return s.replace(before,after,1)

def main()->None:
    master=json.loads(fetch(EXEC_REPO,BASE_MASTER))
    controls=json.loads(fetch(EXEC_REPO,BASE_CONTROL))
    policy=json.loads(fetch(EXEC_REPO,BASE_POLICY))
    stage=fetch(PRODUCT_REPO,CANDIDATE_STAGE)
    if len(stage)>MAX_FILE:
        raise ValueError("candidate stage size over policy")
    source=stage.decode("utf-8-sig")
    for marker in ("Critical WinBot runtime readiness failed; refusing to write .provisioned",
                   "OpenSSH critical setup failed",
                   "Python package setup failed; continuing with independent critical tools",
                   "choco install gsudo"):
        if marker not in source:
            raise ValueError("candidate stage marker missing")
    if (master["source_revision"]!=BASE_SOURCE or
        master["projection_identity_sha256"]!=BASE_PROJECTION or
        master["control_manifest_sha"]!=BASE_CONTROL or
        controls["source_revision"]!=BASE_SOURCE or
        controls["projection_identity_sha256"]!=BASE_PROJECTION or
        controls["stage_provision_blob"]!=BASE_STAGE or
        master["construction"]["stage_provision_blob"]!=BASE_STAGE):
        raise ValueError("baseline graph authority drift")
    auth=policy["authorization"]
    if (policy["state"]!="authorized" or auth["approved_revision"]!=BASE_SOURCE
        or auth["approved_manifest_sha256"]!=BASE_PROJECTION):
        raise ValueError("baseline policy is not exact")
    # Crucial: policy for the newly changed source is NOT authorized.
    if auth["approved_revision"]==CANDIDATE_SOURCE or auth["approved_manifest_sha256"]==CANDIDATE_PROJECTION:
        raise ValueError("unexpected prior owner authorization; reconcile before preparing")
    original_batches=[]
    for sha in master["source_batch_manifests"]:
        b=json.loads(fetch(EXEC_REPO,sha))
        if b["source_revision"]!=BASE_SOURCE:
            raise ValueError("batch source authority drift")
        original_batches.append(b)
    all_old=[e for b in original_batches for e in b["entries"]]
    old_paths=[e["path"] for e in all_old]
    if len(old_paths)!=82 or len(set(old_paths))!=82 or old_paths.count(STAGE)!=1:
        raise ValueError("baseline path set drift")
    for e in all_old:
        if e["path"]==STAGE and e["git_blob_sha"]!=BASE_STAGE:
            raise ValueError("stage baseline blob mismatch")
        if not e["path"].startswith(("guest/","host/","rdte/")) or e["path"].startswith((".git/",".github/")):
            raise ValueError("baseline path not policy-compatible")
    new_batches=[]
    for b in original_batches:
        nb=json.loads(json.dumps(b))
        nb["source_revision"]=CANDIDATE_SOURCE
        for e in nb["entries"]:
            if e["path"]==STAGE:
                e["git_blob_sha"]=CANDIDATE_STAGE
                e["size"]=len(stage)
        new_batches.append(nb)
    def read_entry(e):
        raw=stage if e["path"]==STAGE else fetch(EXEC_REPO,e["git_blob_sha"])
        if len(raw)!=e["size"] or len(raw)>MAX_FILE:
            raise ValueError("projection entry byte count/policy mismatch")
        return {"path":e["path"],"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    new_entries=[e for b in new_batches for e in b["entries"]]
    with ThreadPoolExecutor(max_workers=8) as pool:
        projected=list(pool.map(read_entry,sorted(new_entries,key=lambda x:x["path"])))
    total=sum(e["bytes"] for e in projected)
    if total>MAX_TOTAL or total!=1054722:
        raise ValueError("projection byte count or size policy mismatch")
    idobj={"source_revision":CANDIDATE_SOURCE,"projected_files":projected}
    identity=hashlib.sha256(json.dumps(idobj,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if identity!=CANDIDATE_PROJECTION:
        raise ValueError("independent candidate projection mismatch")
    batch_shas=[blob_sha(encode(b)) for b in new_batches]
    cc=json.loads(json.dumps(controls))
    cc["source_revision"]=CANDIDATE_SOURCE
    cc["projection_identity_sha256"]=CANDIDATE_PROJECTION
    cc["stage_provision_blob"]=CANDIDATE_STAGE
    # Existing projection-policy file stays old and thus MUST reject execution.
    policy_entries=[e for e in cc["entries"] if e["path"]=="rdte/gha/projection-policy.json"]
    if len(policy_entries)!=1 or policy_entries[0]["git_blob_sha"]!=BASE_POLICY:
        raise ValueError("policy gate was unexpectedly changed")
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
    next_master_sha=blob_sha(encode(mm))
    w=fetch(EXEC_REPO,BASE_WRAPPER).decode("utf-8-sig")
    for key,old,new in (
        ("MASTER_MANIFEST_SHA",BASE_MASTER,next_master_sha),
        ("EXPECTED_SOURCE_REVISION",BASE_SOURCE,CANDIDATE_SOURCE),
        ("EXPECTED_PROJECTION_IDENTITY",BASE_PROJECTION,CANDIDATE_PROJECTION),
        ("EXPECTED_CONTROL_MANIFEST_SHA",BASE_CONTROL,control_sha),
    ):
        w=replacement_once(w,key+": '"+old+"'",key+": '"+new+"'")
    # The stage identity is checked twice in the wrapper's reconstruction logic.
    if w.count(BASE_STAGE)!=2:
        raise ValueError("legacy stage pin count drift")
    w=w.replace(BASE_STAGE,CANDIDATE_STAGE)
    w=replacement_once(w,"name: WinBot 9.5 Upstream Dependency Windows A-Only",
        "name: WinBot 9.5 Candidate Provision Fix Dormant A-Only")
    w=replacement_once(w,"'winbot-95-dependency-a-only-20261009-01'",
        "'winbot-95-candidate-not-admitted'")
    if ("agent-dispatch-heavyweight-rdte" not in w or
        "cancel-in-progress: false" not in w or "queue: max" not in w):
        raise ValueError("heavyweight serialization changed")
    # Crucial: A safe derived wrapper is NOT committed to a live workflow path.
    wrapper_sha=blob_sha(w.encode("utf-8"))
    receipt={
        "classification":"EXACT_SUCCESSOR_GRAPH_REVIEW_PREVIEW",
        "source_revision":CANDIDATE_SOURCE,
        "projection_identity_sha256":identity,
        "candidate_stage_blob":CANDIDATE_STAGE,
        "changed_projected_paths":[STAGE],
        "projected_file_count":len(projected),
        "projected_bytes":total,
        "source_batch_manifest_git_blobs":batch_shas,
        "successor_control_manifest_blob":control_sha,
        "successor_master_manifest_blob":next_master_sha,
        "dormant_wrapper_candidate_blob":wrapper_sha,
        "policy_blob_in_graph":BASE_POLICY,
        "product_approval_state":"NOT_AUTHORIZED",
        "policy_revision_authorized_for_candidate":False,
        "git_writes":False,
        "new_workflow_created":False,
        "heavy_guest_launched":False,
        "seed_admitted":False,
        "terminal_admitted":False,
    }
    p=Path(os.environ["RUNNER_TEMP"])/"winbot-95-successor-graph-preview.json"
    p.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__":
    main()
