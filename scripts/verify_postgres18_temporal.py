#!/usr/bin/env python3
"""Independent expected source/temporal oracle for original PostgreSQL 18."""
import argparse
import hashlib
import json
from pathlib import Path
import re

EXPECTED={
    "before_any":("NEITHER",0,0,0),
    "early_known":("REFUTED",1,0,1),
    "late_retro":("BOTH",3,1,1),
    "pre_arrival":("REFUTED",1,0,1),
    "later_known":("BOTH",2,1,1),
    "late_reacquisition":("BOTH",3,1,1),
    "beta_private":("SUPPORTED",1,1,0),
    "alpha_unknown":("NEITHER",0,0,0)
}
FIELDS={"schema","classification","engine","image_id","image_tag",
        "image_digest_pinned","version_locked",
        "source_occurrences","claim_observations","case_count","results",
        "native_without_overlaps_verified","source_immutability_verified",
        "source_tenant_constraint_verified","replay_restart_verified",
        "model_inference","real_mail","elapsed_seconds"}

def verify(receipt,source_sha,run_id,digest):
    raw=Path(receipt).read_bytes()
    if len(raw)>12000 or hashlib.sha256(raw).hexdigest()!=digest:
        raise ValueError("RECEIPT_INTEGRITY_INVALID")
    value=json.loads(raw)
    if not isinstance(value,dict) or set(value)!=FIELDS:
        raise ValueError("POSTGRES_RECEIPT_SHAPE_DRIFT")
    if (value["schema"]!="mail-public-postgres18-temporal-v1" or
        value["classification"]!="REAL_POSTGRES18_TEMPORAL_SQL_PROJECTION" or
        value["engine"]!="PostgreSQL 18" or
        value["image_tag"]!="postgres:18.3" or
        not re.fullmatch(r"sha256:[a-f0-9]{64}",value["image_id"]) or
        value["image_digest_pinned"] is not False or
        value["version_locked"] is not False or
        value["source_occurrences"]!=6 or value["claim_observations"]!=6 or
        value["case_count"]!=8 or
        value["native_without_overlaps_verified"] is not True or
        value["source_immutability_verified"] is not True or
        value["source_tenant_constraint_verified"] is not True or
        value["replay_restart_verified"] is not True or
        value["model_inference"] is not False or value["real_mail"] is not False or
        not isinstance(value["elapsed_seconds"],(float,int)) or
        not 0<value["elapsed_seconds"]<=400 or
        not re.fullmatch(r"[a-f0-9]{40}",source_sha) or
        not re.fullmatch(r"[0-9]+",run_id)):
        raise ValueError("POSTGRES_SOURCE_OR_RUNTIME_SCOPE_INVALID")
    seen=value["results"]
    if not isinstance(seen,dict) or set(seen)!=set(EXPECTED):
        raise ValueError("POSTGRES_CASE_SET_CHANGED")
    for id,(state,count,pos,neg) in EXPECTED.items():
        item=seen[id]
        if (not isinstance(item,dict) or
            set(item)!={"status","sources","support_lineages","refute_lineages"} or
            (item["status"],len(item["sources"]),item["support_lineages"],
             item["refute_lineages"])!=(state,count,pos,neg) or
            len(item["sources"])!=len(set(item["sources"]))):
            raise ValueError("INDEPENDENT_POSTGRES_GOLD_MISMATCH_"+id)
    if ("beta1" in seen["late_retro"]["sources"] or
        "a5" in seen["late_reacquisition"]["sources"] or
        seen["late_reacquisition"]["sources"]!=["a1","a2","a4"]):
        raise ValueError("POSTGRES_CROSS_TENANT_OR_PLANNED_CLAIM_LEAK")
    return {"schema":"public-postgres18-verification/v1",
            "verdict":"PASS","image_id":value["image_id"],
            "github_source_sha":source_sha,"github_run_id":run_id,
            "receipt_sha256":digest,"qualified_cases":8}

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    for field in ("receipt","source-sha","run-id","sha256","out"):
        ap.add_argument("--"+field,required=True)
    args=ap.parse_args()
    r=verify(args.receipt,args.source_sha,args.run_id,args.sha256)
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
    print("POSTGRES_TEMPORAL_INDEPENDENT_VERDICT=PASS")
