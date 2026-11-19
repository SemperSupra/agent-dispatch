#!/usr/bin/env python3
"""Independent exact-receipt and native source guard for public SWI workcell."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"tools/mail-evidence-challenge/temporal_prior_art/swi_temporal.pl"
FIELDS={"schema","classification","source_sha256","swi_version",
        "test_count_per_run","run_count","original_swi_executed",
        "real_mail","model_inference","source_occurrences",
        "contradictions_preserved","tenant_scope_verified",
        "derived_proof_guard","replay_verified","version_hash_locked"}

def verify(path,source_sha,run_id,receipt_sha):
    raw=Path(path).read_bytes()
    if len(raw)>4096 or hashlib.sha256(raw).hexdigest()!=receipt_sha:
        raise ValueError("RECEIPT_SHA_MISMATCH")
    obj=json.loads(raw)
    if set(obj)!=FIELDS:
        raise ValueError("RECEIPT_FIELD_DRIFT")
    source=SOURCE.read_bytes()
    if (obj["schema"]!="public-native-swi-temporal/v1" or
        obj["classification"]!="NATIVE_PROLOG_SYNTHETIC_EVIDENCE_ONLY" or
        obj["source_sha256"]!=hashlib.sha256(source).hexdigest() or
        not re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+",obj["swi_version"]) or
        obj["test_count_per_run"]!=12 or obj["run_count"]!=2 or
        obj["source_occurrences"]!=8 or
        obj["original_swi_executed"] is not True or
        obj["contradictions_preserved"] is not True or
        obj["tenant_scope_verified"] is not True or
        obj["derived_proof_guard"] is not True or
        obj["replay_verified"] is not True or
        obj["version_hash_locked"] is not False or
        obj["model_inference"] is not False or
        obj["real_mail"] is not False or
        not re.fullmatch(r"[0-9a-f]{40}",source_sha) or
        not re.fullmatch(r"[0-9]+",run_id)):
        raise ValueError("NATIVE_SWI_PROVENANCE_OR_SCOPE_INVALID")
    return {"schema":"public-swi-verification/v1",
            "independent_verdict":"PASS","github_source_sha":source_sha,
            "github_run_id":run_id,"source_sha256":obj["source_sha256"],
            "receipt_sha256":receipt_sha}

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    for key in ("receipt","source-sha","run-id","sha256","out"):
        ap.add_argument("--"+key,required=True)
    a=ap.parse_args()
    result=verify(a.receipt,a.source_sha,a.run_id,a.sha256)
    out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True)+"\n",encoding="utf-8")
    print("SWI_TEMPORAL_INDEPENDENT_VERDICT=PASS")
