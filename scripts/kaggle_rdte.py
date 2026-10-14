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
    "tpu-v5e8-device-v1": ("tpu_device.py", "TpuV5E8", "TPU", 600),
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
    # Protect Kaggle's remote-session quota across short-lived GHA invocations.
    # A workflow-level concurrency group ceases protecting after 'submit' exits,
    # while Kaggle may still be QUEUED or RUNNING for minutes.
    token = None
    seen = set()
    other_owned = []
    expected_owner = ref.split("/", 1)[0].lower()
    for _ in range(20):
        kw = {"mine":True,"page_size":100}
        if token: kw["page_token"] = token
        response = api.kernels_list_with_response(**kw)
        if response is None or not hasattr(response,"kernels"):
            raise Denied("PROVIDER_LIST_UNAVAILABLE")
        for entry in (response.kernels or []):
            row = getattr(entry,"ref",None)
            if not isinstance(row,str) or "/" not in row:
                raise Denied("PROVIDER_LIST_UNTRUSTED")
            if row.lower() == ref.lower():
                return True
            owner, slug = row.split("/",1)
            if owner.lower() == expected_owner and slug.lower().startswith("ad-rdte-"):
                other_owned.append(row)
                if len(other_owned)>32:
                    raise Denied("OWNED_EXPERIMENT_SCAN_BOUND_EXCEEDED")
        token = getattr(response,"next_page_token",None)
        if not token:
            break
        if not isinstance(token,str) or token in seen:
            raise Denied("PROVIDER_PAGING_UNKNOWN")
        seen.add(token)
    else:
        raise Denied("PROVIDER_LIST_BOUND_EXCEEDED")
    for other in other_owned:
        state = str(getattr(api.kernels_status(other),"status","UNKNOWN")).upper()
        if any(x in state for x in ("QUEUED","RUNNING","PENDING","STARTING")):
            raise Denied("ANOTHER_AGENT_DISPATCH_KAGGLE_JOB_ACTIVE")
        if not any(x in state for x in ("COMPLETE","ERROR","FAIL","CANCEL","SUCCESS")):
            raise Denied("EXISTING_KAGGLE_JOB_STATE_UNKNOWN")
    return False

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

def require_current_native_version(api, owner, slug, required):
    """Refuse observations when Kaggle's latest is not the requested version.

    Kaggle CLI 2.2.4 parses a /version suffix in kernels_status/output but
    DOES NOT forward it to the underlying status/output request. Check actual
    current version through the native get_kernel metadata before AND after
    output retrieval, avoiding a stale/wrong-version PASS.
    """
    from kagglesdk.kernels.types.kernels_api_service import ApiGetKernelRequest
    request = ApiGetKernelRequest()
    request.user_name = owner
    request.kernel_slug = slug
    with api.build_kaggle_client() as kaggle:
        response = kaggle.kernels.kernels_api_client.get_kernel(request)
    metadata = getattr(response, "metadata", None)
    current = getattr(metadata, "current_version_number", None)
    if not isinstance(current, int) or current < 1:
        raise Denied("PROVIDER_NATIVE_VERSION_NOT_ATTESTED")
    if current != required:
        raise Denied("PROVIDER_VERSION_CHANGED_RECONCILE")
    return current


def observe(api, plan, path: Path):
    user = account(api)
    slug = plan["notebook_slug"]
    ref = f'{user}/{slug}/{plan["version"]}'
    require_current_native_version(api, user, slug, plan["version"])
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
    require_current_native_version(api, user, slug, plan["version"])
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
                   "NO_ACCELERATOR","GPU_COUNT_MISMATCH","GPU_MODEL_MISMATCH",
                   "TPU_JAX_RUNTIME_MISSING","TPU_COUNT_MISMATCH",
                   "TPU_RUNTIME_EXECUTION_ERROR","TPU_MATH_ORACLE_FAILED",
                   "CUDA_BUILD_UNAVAILABLE_DEVICE_UNKNOWN","CPU_ONLY_TORCH_ON_GPU",
                   "CUDA_RUNTIME_MISMATCH_ON_VISIBLE_GPU","RuntimeError","AssertionError","UNKNOWN"}
        klass = failure if failure in allowed else "UNCLASSIFIED"
        hardware = {"GPU_COUNT_MISMATCH","GPU_MODEL_MISMATCH","TPU_COUNT_MISMATCH"}
        software = {"CPU_ONLY_TORCH_ON_GPU","CUDA_RUNTIME_MISMATCH_ON_VISIBLE_GPU",
                    "TPU_JAX_RUNTIME_MISSING"}
        allocation_unknown = {"CUDA_DEVICE_UNAVAILABLE","TPU_DEVICE_UNAVAILABLE",
                              "CUDA_BUILD_UNAVAILABLE_DEVICE_UNKNOWN"}
        if klass in hardware:
            category = "FAIL_HARDWARE_MISMATCH"
        elif klass in software:
            category = "FAIL_RUNTIME_SOFTWARE"
        elif klass in allocation_unknown:
            category = "FAIL_DEVICE_NOT_ATTESTED"
        else:
            category = "FAIL_WORKLOAD"
        return {"state":state,"is_terminal":True,
                "classification":category,
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
    elif workload=="tpu-v5e8-device-v1":
        m=data.get("metrics",{})
        if (not isinstance(m,dict)
            or m.get("requested_accelerator")!="TpuV5E8"
            or m.get("tpu_count")!=8
            or m.get("jax_backend_tpu") is not True
            or m.get("tpu_arithmetic") is not True):
            raise Denied("TPU_HARDWARE_ATTESTATION_FAILED")
    else:
        m=data.get("metrics",{})
        if (not isinstance(m,dict) or m.get("accelerator")!="tpu"
            or m.get("tpu_count",0)<1
            or m.get("scope")!="synthetic-method-sanity-only"
            or m.get("heldout_cosine",0)<0.75
            or m.get("heldout_cosine",0)-m.get("shuffled_control_cosine",0)<0.45):
            raise Denied("TPU_OR_SYNTHETIC_BRIDGE_ORACLE_FAILED")

def write_control_receipt(out: Path, record):
    """Publish only a fixed allowlist, never raw SDK/provider exception text."""
    allowed = {"schema","action","assignment_id","workload","accelerator",
               "source_sha256","limit_seconds","state","is_terminal",
               "classification","failure_class","native_version","result_digest"}
    if not isinstance(record,dict) or record.get("schema")!=SCHEMA:
        raise Denied("CONTROL_RECEIPT_SCHEMA_INVALID")
    filtered = {k:record[k] for k in allowed if k in record}
    encoded = (json.dumps(filtered,sort_keys=True,indent=2)+"\n").encode("utf-8")
    if len(encoded)>16384:
        raise Denied("CONTROL_RECEIPT_TOO_LARGE")
    out.mkdir(parents=True,exist_ok=True)
    (out/"control-receipt.json").write_bytes(encoded)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--action",required=True,choices=("plan","submit","observe"))
    p.add_argument("--assignment",required=True)
    p.add_argument("--workload",required=True,choices=tuple(WORKLOADS))
    p.add_argument("--version",type=int,default=0)
    p.add_argument("--out-dir",default=".kaggle-rdte")
    a=p.parse_args()
    out=Path(a.out_dir)
    public=None
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
            write_control_receipt(out,record)
        print("KAGGLE_RDTE_STATE="+str(record["state"]))
        # Terminal failed is durable evidence, not a qualifying operation.
        return 2 if result.get("state")=="TERMINAL_FAILED" else 0
    except Denied as error:
        reason=str(error)
        # Only stable all-uppercase local failure classes cross this boundary.
        if not re.fullmatch(r"[A-Z0-9_]{4,96}",reason):
            reason="UNCLASSIFIED_ADMISSION_DENIAL"
    except Exception:
        reason="PROVIDER_RUNTIME_UNKNOWN_RECONCILE"
    if a.action!="plan":
        record={"schema":SCHEMA,**(public or {}),
                "state":"BLOCKED","is_terminal":False,
                "classification":"FAIL_CLOSED","failure_class":reason}
        try:
            write_control_receipt(out,record)
        except (OSError,Denied):
            pass
    print("KAGGLE_RDTE_BLOCKED="+reason,file=sys.stderr)
    return 2

if __name__=="__main__":
    sys.exit(main())
