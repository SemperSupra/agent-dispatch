#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib
from typing import Any

class FixtureError(RuntimeError):
    pass

def load(path:pathlib.Path)->dict[str,Any]:
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise FixtureError("fixture registry must be an object")
    return value

def valid_sha(value:Any)->bool:
    return isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value)

def validate(data:dict[str,Any])->dict[str,Any]:
    if data.get("schema")!="semper-supra.compute-guest-fixtures/v1":
        raise FixtureError("unsupported schema")
    policy=data.get("policy")
    if not isinstance(policy,dict) or any(policy.get(k) is not True for k in (
        "immutable_binary_digest_required",
        "windows_product_key_prohibited",
        "windows_provider_url_may_be_ephemeral",
        "windows_iso_must_be_hash_verified",
        "source_identity_is_not_runtime_qualification",
        "nested_kvm_must_be_observed_before_firecracker",
    )):
        raise FixtureError("fixture policy incomplete")
    fixtures=data.get("fixtures")
    if not isinstance(fixtures,dict):
        raise FixtureError("fixtures missing")
    fc=fixtures.get("firecracker_x86_64")
    if not isinstance(fc,dict) or fc.get("status")!="SOURCE_PINNED":
        raise FixtureError("Firecracker source must be pinned")
    if fc.get("release")!="v1.17.0" or fc.get("asset_name")!="firecracker-v1.17.0-x86_64.tgz":
        raise FixtureError("Firecracker release identity drifted")
    if not valid_sha(fc.get("sha256")):
        raise FixtureError("Firecracker SHA-256 missing")
    if fc.get("runtime_preconditions")!=["linux-guest","/dev/kvm-readable","/dev/kvm-writable"]:
        raise FixtureError("Firecracker KVM preconditions drifted")
    win=fixtures.get("windows11_enterprise_eval_x64")
    if not isinstance(win,dict) or win.get("status")!="ACQUIRE_AND_VERIFY":
        raise FixtureError("Windows source must remain acquire-and-verify")
    if win.get("product_key_required") is not False:
        raise FixtureError("Windows fixture must not require/embed a product key")
    if win.get("download_url_policy")!="provider-issued-ephemeral":
        raise FixtureError("Windows download URL must not be statically treated as immutable")
    if win.get("expected_sha256") is not None:
        raise FixtureError("Windows hash must remain unset until exact provider media is acquired")
    required=set(win.get("acquisition_receipt_required") or [])
    if required!={"observed_product_version","iso_filename","sha256","provider_hash_reference","acquired_at"}:
        raise FixtureError("Windows acquisition receipt contract incomplete")
    return {
      "schema":"semper-supra.compute-guest-fixtures-validation/v1",
      "status":"PASS",
      "firecracker":fc["release"],
      "windows_source_status":win["status"],
      "runtime_claims":"OPEN"
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--fixtures",type=pathlib.Path,default=pathlib.Path("config/compute-guest-fixtures.json"))
    a=ap.parse_args()
    try:
        result=validate(load(a.fixtures))
    except (FixtureError,OSError,json.JSONDecodeError) as exc:
        print(json.dumps({"status":"ERROR","error":str(exc)},sort_keys=True))
        return 2
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
