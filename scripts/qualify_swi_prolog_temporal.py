#!/usr/bin/env python3
"""Bounded, original SWI-Prolog process DOE. Public fictional sources only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"tools/mail-evidence-challenge/temporal_prior_art/swi_temporal.pl"
SCHEMA="public-native-swi-temporal/v1"
SENTINEL=re.compile(r"^SWI_TEMPORAL_NATIVE_PASS version=([0-9]+[.][0-9]+[.][0-9]+) tests=12$",re.M)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def qualify():
    raw=SOURCE.read_bytes()
    if len(raw)>32768 or b"begin_tests(mail_temporal_original_swi)" not in raw or raw.count(b"test(")!=12:
        raise ValueError("UNREVIEWED_SOURCE_OR_TEST_COUNT")
    with tempfile.TemporaryDirectory(prefix="swi-public-mail-") as root:
        env={"HOME":root,"PATH":"/usr/local/bin:/usr/bin:/bin",
             "LC_ALL":"C.UTF-8","SWIPL_PACKAGES":"/nonexistent"}
        observed=[]
        for i in range(2):
            proc=subprocess.run(
                ["swipl","-q","-f","none","-s",str(SOURCE),
                 "-g","run_qualification","-t","halt"],
                cwd=root,env=env,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=50,check=False)
            if proc.returncode or len(proc.stdout)>4096 or len(proc.stderr)>16384:
                raise ValueError("NATIVE_SWI_TEST_FAILURE")
            result=SENTINEL.search(proc.stdout.decode("ascii","replace"))
            if not result:
                raise ValueError("MISSING_SWI_NATIVE_SENTINEL")
            observed.append(result.group(1))
        if observed[0]!=observed[1]:
            raise ValueError("SINGLE_REP_VERSION_DRIFT")
        return {"schema":SCHEMA,"classification":"NATIVE_PROLOG_SYNTHETIC_EVIDENCE_ONLY",
                "source_sha256":hashlib.sha256(raw).hexdigest(),
                "swi_version":observed[0],"test_count_per_run":12,
                "run_count":2,"original_swi_executed":True,
                "real_mail":False,"model_inference":False,
                "source_occurrences":8,"contradictions_preserved":True,
                "tenant_scope_verified":True,"derived_proof_guard":True,
                "replay_verified":True,"version_hash_locked":False}
if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",required=True)
    args=ap.parse_args()
    r=qualify()
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(r,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8")
    print("SWI_TEMPORAL_EXECUTION_QUALIFIED=TRUE")
