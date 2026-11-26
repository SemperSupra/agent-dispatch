#!/usr/bin/env python3
"""Execute real SWI-Prolog on fictional mail evidence, with bounded receipt.

Only the reviewed local Prolog file is passed to the interpreter. All input
data is hardcoded fictional and the subprocess does not inherit credentials.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
PROGRAM=ROOT/"tools/mail-evidence-challenge/temporal_prolog/qualify.pl"
SCHEMA="public-mail-temporal-original-swi-prolog-r2"
REQUIRED={
    "retroactive_known_at_veto","both_preserved","planned_not_actual",
    "cross_tenant_denied","lineages_not_extra_votes",
    "derivation_source_backed","later_refutation_quarantined",
    "actual_interpreter",
}

class Blocked(ValueError):
    pass

def run(args:list[str],cwd:Path,env:dict[str,str],timeout:int)->subprocess.CompletedProcess[bytes]:
    try:
        p=subprocess.run(args,cwd=cwd,env=env,
                         stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,timeout=timeout,check=False)
    except subprocess.TimeoutExpired as exc:
        raise Blocked("NATIVE_SWIPL_TIMEOUT") from exc
    if p.returncode:
        # Untrusted input can never inject a shell or arbitrary file path.
        # Keep raw interpreter stderr private to the disposable runner.
        raise Blocked("NATIVE_SWIPL_NONZERO_EXIT_"+str(p.returncode))
    if len(p.stdout)>8192 or len(p.stderr)>32768:
        raise Blocked("UNBOUNDED_INTERPRETER_OUTPUT")
    return p

def qualify()->dict:
    if not PROGRAM.is_file() or PROGRAM.stat().st_size>16384:
        raise Blocked("REVIEWED_PROLOG_SOURCE_MISSING")
    source_sha=hashlib.sha256(PROGRAM.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="mail-swipl-public-") as directory:
        home=Path(directory)
        env={"HOME":str(home),"PATH":"/usr/local/bin:/usr/bin:/bin",
             "LANG":"C.UTF-8","SWI_HOME_DIR":"","PYTHONNOUSERSITE":"1"}
        env.pop("SWI_HOME_DIR")
        version=run(["swipl","--version"],home,env,8).stdout.decode("utf-8","replace").strip()
        if not re.search(r"SWI-Prolog version (9|10)\.",version):
            raise Blocked("SWI_INTERPRETER_RELEASE_UNREVIEWED")
        output=run(["swipl","-q","-s",str(PROGRAM),"-g","qualify","-t","halt"],
                   home,env,50)
        try:
            result=json.loads(output.stdout)
        except (UnicodeDecodeError,ValueError) as exc:
            raise Blocked("NON_JSON_NATIVE_REASONING_RECORD") from exc
        if (not isinstance(result,dict) or result.get("schema")!=SCHEMA
                or result.get("classification")!="ORIGINAL_SWI_PROLOG_SOURCE_REPLAY"
                or result.get("source_occurrences")!=8
                or result.get("independent_test_cases")!=9
                or any(result.get(key) is not True for key in REQUIRED)
                or result.get("model_inference") is not False
                or result.get("native_pst_qualified") is not False):
            raise Blocked("PROLOG_SOURCE_ORACLE_MISMATCH")
        # Independently rerun original interpreter from a second clean state.
        replay=run(["swipl","-q","-s",str(PROGRAM),"-g","qualify","-t","halt"],
                   home,env,50)
        if output.stdout!=replay.stdout:
            raise Blocked("PROLOG_CLEAN_REPLAY_DRIFT")
        return {
            "schema":SCHEMA,
            "classification":"PASS_ORIGINAL_SWI_LOGIC_ONLY",
            "interpreter_version":version,
            "source_sha256":source_sha,
            "native_engine_executed":True,
            "source_occurrences":8,
            "independent_test_cases":9,
            "clean_replay_verified":True,
            "support_and_refutation_retained":True,
            "cross_tenant_blocked":True,
            "derivation_quarantined":True,
            "model_inference":False,
            "native_pst_qualified":False,
            "stdout_sha256":hashlib.sha256(output.stdout).hexdigest()
        }

if __name__=="__main__":
    print(json.dumps(qualify(),sort_keys=True,separators=(",",":")))
