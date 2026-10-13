#!/usr/bin/env python3
"""Typed, one-shot Kaggle notebook dispatch/observe. All provider identifiers stay local.

Public GHA is a launcher, not a shell-as-a-service or a scientific authority.
Exit 0 only on a verified operation. No automatic retries, queue or tunnel.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

WORKLOADS = {
    "gpu-cuda-smoke-v1": ("gpu_smoke.py", "NvidiaTeslaT4", "GPU", 600),
    "tpu-jax-bridge-v1": ("tpu_bridge.py", "TpuV5E8", "TPU", 1200),
}
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{3,33}$")
ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "experiments" / "kaggle_rdte"
SCHEMA = "kaggle-rdte-control/v1"

class Denied(Exception):
    pass

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def validate(action: str, assignment: str, workload: str, version: int = 0):
    if action not in ("plan", "submit", "observe") or workload not in WORKLOADS:
        raise Denied("UNKNOWN_TYPED_OPERATION")
    if not SLUG.fullmatch(assignment):
        raise Denied("INVALID_ASSIGNMENT_ID")
    if action == "observe" and not (0 < version <= 999999):
        raise Denied("OBSERVE_REQUIRES_EXACT_VERSION")
    filename, accel, kind, limit = WORKLOADS[workload]
    source = SOURCES / filename
    if not source.is_file():
        raise Denied("APPROVED_SOURCE_MISSING")
    return {"action": action, "assignment_id": assignment, "workload": workload,
            "notebook_slug": "ad-rdte-" + assignment,
            "accelerator": accel, "quota_kind": kind, "limit_seconds": limit,
            "source_path": str(source), "source_sha256": digest(source.read_bytes()),
            "version": version}

def account(api) -> str:
    api.authenticate()
    user = api.get_config_value(api.CONFIG_NAME_USER)
    if not isinstance(user,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}",user):
        raise Denied("PROVIDER_IDENTITY_UNAVAILABLE")
    return user

def quota_ok(api, kind, seconds):
    q = api.quota_view()
    resource = q.gpu_quota if kind == "GPU" else q.tpu_quota
    if resource is None or resource.time_used is None or resource.total_time_allowed is None:
        raise Denied("PROVIDER_QUOTA_UNKNOWN")
    remaining = (resource.total_time_allowed-resource.time_used).total_seconds()
    if remaining < seconds + 300:
        raise Denied("PROVIDER_QUOTA_INSUFFICIENT")
    return int(remaining)

def existing(api, ref):
    token = None
    seen = set()
    for _ in range(20):
        kw = {"mine":True,"page_size":100}
        if token: kw["page_token"] = token
        response = api.kernels_list_with_response(**kw)
        if response is None or not hasattr(response,"kernels"):
            raise Denied("PROVIDER_LIST_UNAVAILABLE")
        for entry in (response.kernels or []):
            row = getattr(entry,"ref",None)
            if not isinstance(row,str): raise Denied("PROVIDER_LIST_UNTRUSTED")
            if row.lower() == ref.lower(): return True
        token = getattr(response,"next_page_token",None)
        if not token: return False
        if not isinstance(token,str) or token in seen: raise Denied("PROVIDER_PAGING_UNKNOWN")
        seen.add(token)
    raise Denied("PROVIDER_LIST_BOUND_EXCEEDED")

def submit(api, plan):
    user = account(api)
    quota_ok(api, plan["quota_kind"],plan["limit_seconds"])
    ref = f'{user}/{plan["notebook_slug"]}'
    if existing(api,ref):
        raise Denied("TARGET_ALREADY_EXISTS_RECONCILE_FIRST")
    source = Path(plan["source_path"])
    with tempfile.TemporaryDirectory(prefix="kaggle-rdte-") as temp:
        folder = Path(temp)
        (folder/"run.py").write_bytes(source.read_bytes())
        metadata = {
            "id":ref,"title":plan["notebook_slug"],"code_file":"run.py",
            "language":"python","kernel_type":"script","is_private":True,
            "enable_gpu":plan["quota_kind"]=="GPU",
            "enable_tpu":plan["quota_kind"]=="TPU",
            "enable_internet":False, "machine_shape":plan["accelerator"],
            # Kaggle backend investigation #1197: CPU/GPU docker_image SHA can
            # override TPU VM allocation. Use unpinned latest runtime only.
            "docker_image_pinning_type":"latest",
            "dataset_sources":[],"competition_sources":[],"kernel_sources":[],
            "model_sources":[]
        }
        (folder/"kernel-metadata.json").write_text(json.dumps(metadata)+"\n")
        # Provider-native structured response; CLI exit status is NOT sufficient.
        outcome = api.kernels_push(str(folder),timeout=str(plan["limit_seconds"]),
                                   acc=plan["accelerator"])
    if outcome is None or getattr(outcome,"error",None):
        raise Denied("PROVIDER_SUBMISSION_REJECTED_OR_UNKNOWN")
    version = getattr(outcome,"versionNumber",None)
    if not isinstance(version,int) or version < 1:
        raise Denied("PROVIDER_SUBMITTED_BUT_VERSION_UNKNOWN_RECONCILE")
    return {"native_version":version,"state":"SUBMITTED","is_terminal":False}

def observe(api, plan, path: Path):
    user = account(api)
    ref = f'{user}/{plan["notebook_slug"]}/{plan["version"]}'
    status = api.kernels_status(ref)
    value = str(getattr(status,"status","UNKNOWN")).upper()
    if "COMPLETE" in value or "SUCCESS" in value:
        state = "TERMINAL_COMPLETE"
    elif "ERROR" in value or "FAIL" in value or "CANCEL" in value:
        state = "TERMINAL_FAILED"
    else:
        return {"state":"NONTERMINAL_OR_UNKNOWN","is_terminal":False}
    # Retrieve even from ERROR: device-provisioning failures are evidence, not
    # reasons to discard the notebook's fail-closed diagnostic receipt.
    path.mkdir(parents=True,exist_ok=True)
    try:
        api.kernels_output(ref,str(path),file_pattern=r"^kaggle_rdte_result[.]json$",
                           force=False,quiet=True)
    except Exception:
        if state == "TERMINAL_FAILED":
            return {"state":state,"is_terminal":True,"classification":"FAIL_PROVIDER_NO_RECEIPT"}
        raise Denied("PROVIDER_OUTPUT_UNAVAILABLE")
    receipt = path/"kaggle_rdte_result.json"
    if not receipt.is_file() or receipt.stat().st_size > 65536:
        if state == "TERMINAL_FAILED":
            return {"state":state,"is_terminal":True,"classification":"FAIL_PROVIDER_NO_RECEIPT"}
        raise Denied("MISSING_OR_OVERSIZED_RECEIPT")
    try:
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError,UnicodeError,ValueError):
        raise Denied("INVALID_RECEIPT")
    if state == "TERMINAL_FAILED":
        # Allowlist rather than projecting provider log bodies/private values.
        failure = str(data.get("failure_class","")) if isinstance(data,dict) else ""
        allowed = {"CUDA_DEVICE_UNAVAILABLE","CUDA_BUILD_UNAVAILABLE",
                   "TPU_DEVICE_UNAVAILABLE","SYNTHETIC_BRIDGE_CONTROL_FAILED",
                   "NO_ACCELERATOR","GPU_COUNT_MISMATCH","GPU_MODEL_MISMATCH","RuntimeError","AssertionError","UNKNOWN"}
        klass = failure if failure in allowed else "UNCLASSIFIED"
        return {"state":state,"is_terminal":True,
                "classification":"FAIL_HARDWARE" if klass in
                  {"CUDA_DEVICE_UNAVAILABLE","CUDA_BUILD_UNAVAILABLE","TPU_DEVICE_UNAVAILABLE",
                   "NO_ACCELERATOR","GPU_COUNT_MISMATCH","GPU_MODEL_MISMATCH"} else "FAIL_WORKLOAD",
                "failure_class":klass,"result_digest":digest(receipt.read_bytes()),
                "native_version":plan["version"]}
    verify(data,plan["workload"])
    return {"state":"TERMINAL_VERIFIED","is_terminal":True,"classification":"PASS",
            "native_version":plan["version"],"result_digest":digest(receipt.read_bytes())}

def verify(data, workload):
    if not isinstance(data,dict) or data.get("schema")!="kaggle-rdte-result/v1":
        raise Denied("RECEIPT_SCHEMA_MISMATCH")
    if data.get("workload")!=workload or data.get("status")!="PASS":
        raise Denied("RECEIPT_WORKLOAD_OR_VERDICT_MISMATCH")
    if workload=="gpu-cuda-smoke-v1":
        if data.get("accelerator")!="gpu" or data.get("gpu_count")!=2 or data.get("checksum")!=8386560.0:
            raise Denied("CUDA_ORACLE_FAILED")
    else:
        m=data.get("metrics",{})
        if (not isinstance(m,dict) or m.get("accelerator")!="tpu"
            or m.get("tpu_count",0)<1
            or m.get("scope")!="synthetic-method-sanity-only"
            or m.get("heldout_cosine",0)<0.75
            or m.get("heldout_cosine",0)-m.get("shuffled_control_cosine",0)<0.45):
            raise Denied("TPU_OR_SYNTHETIC_BRIDGE_ORACLE_FAILED")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--action",required=True,choices=("plan","submit","observe"))
    p.add_argument("--assignment",required=True)
    p.add_argument("--workload",required=True,choices=tuple(WORKLOADS))
    p.add_argument("--version",type=int,default=0)
    p.add_argument("--out-dir",default=".kaggle-rdte")
    a=p.parse_args()
    out=Path(a.out_dir)
    try:
        plan=validate(a.action,a.assignment,a.workload,a.version)
        public={k:plan[k] for k in ("action","assignment_id","workload","accelerator","source_sha256","limit_seconds")}
        if a.action=="plan":
            result={"state":"PLANNED","is_terminal":False}
        else:
            from kaggle import api
            result=submit(api,plan) if a.action=="submit" else observe(api,plan,out)
        record={"schema":SCHEMA,**public,**result}
        if a.action!="plan":
            out.mkdir(parents=True,exist_ok=True)
            (out/"control-receipt.json").write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
        print("KAGGLE_RDTE_STATE="+str(record["state"]))
        return 0
    except Denied as error:
        # No provider exception/body/identity emitted in public GHA logs.
        print("KAGGLE_RDTE_BLOCKED="+str(error),file=sys.stderr)
    except Exception:
        print("KAGGLE_RDTE_BLOCKED=PROVIDER_RUNTIME_UNKNOWN_RECONCILE",file=sys.stderr)
    return 2

if __name__=="__main__":
    sys.exit(main())
