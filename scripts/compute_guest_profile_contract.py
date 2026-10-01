#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib
from typing import Any

class ProfileError(RuntimeError):
    pass

def load(path:pathlib.Path)->dict[str,Any]:
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise ProfileError("profile must be object")
    return value

def validate(p:dict[str,Any])->dict[str,Any]:
    if p.get("schema")!="semper-supra.compute-guest-profiles/v1":
        raise ProfileError("unsupported schema")
    if p.get("dependencies",{}).get("firecracker")!="SemperSupra/agent-dispatch-private#277":
        raise ProfileError("Firecracker authority must remain #277")
    if p.get("dependencies",{}).get("windows_embodiment")!="mark-e-deyoung/windows-utilities#26":
        raise ProfileError("Windows embodiment authority must remain windows-utilities#26")
    policy=p.get("policy")
    if not isinstance(policy,dict) or any(policy.get(k) is not True for k in (
        "source_capability_is_not_runtime_qualification",
        "nested_kvm_must_be_observed_in_guest",
        "private_hypervisor_escape_hatches_prohibited",
        "windows_media_must_be_legal_public_evaluation_or_user_supplied",
        "windows_product_key_must_not_be_embedded",
        "guest_oracle_required_before_backend_admission",
    )):
        raise ProfileError("safety/claim policy incomplete")
    tn=p.get("truenas")
    expected={"25.04.1","25.04.2.6","25.10.7","26.0.0-BETA.3"}
    if not isinstance(tn,dict) or set(tn)!=expected:
        raise ProfileError("TrueNAS guest profile set must cover exact admitted matrix")
    for version,row in tn.items():
        if row.get("windows11",{}).get("runtime_status")!="OPEN":
            raise ProfileError(f"{version}: Windows runtime must remain OPEN before receipt")
        if row.get("firecracker",{}).get("runtime_status")!="OPEN":
            raise ProfileError(f"{version}: Firecracker runtime must remain OPEN before receipt")
        if version=="25.04.1":
            fc=row["firecracker"]
            if fc.get("source_status")!="RUNTIME_OBSERVE_ONLY" or fc.get("cpu_passthrough_control") is not None:
                raise ProfileError("25.04.1 Firecracker must remain observe-only without private raw.qemu")
        else:
            if row["firecracker"].get("cpu_passthrough_control")!="vm.create.cpu_mode=HOST-PASSTHROUGH":
                raise ProfileError(f"{version}: native Firecracker candidate must bind HOST-PASSTHROUGH")
        win=row["windows11"]
        if win.get("source_status")!="CANDIDATE":
            raise ProfileError(f"{version}: Windows source status must remain CANDIDATE")
        caps=win.get("capabilities")
        if not isinstance(caps,dict) or set(caps)!={"secure_boot","tpm","uefi_q35"}:
            raise ProfileError(f"{version}: Windows capability set incomplete")
    prox=p.get("proxmox")
    if not isinstance(prox,dict) or set(prox)!={"9.2-1"}:
        raise ProfileError("only admitted Proxmox 9.2-1 may have guest profile")
    for kind in ("windows11","firecracker"):
        if prox["9.2-1"][kind].get("runtime_status")!="OPEN":
            raise ProfileError(f"Proxmox {kind} runtime must remain OPEN")
    rungs=p.get("rungs")
    if not isinstance(rungs,dict) or list(rungs)!=["V0","V1","V2","W1","WB"]:
        raise ProfileError("guest rung order/coverage invalid")
    return {
        "schema":"semper-supra.compute-guest-profiles-validation/v1",
        "status":"PASS",
        "truenas_versions":sorted(tn),
        "proxmox_versions":sorted(prox),
        "runtime_claims":"OPEN",
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--profile",type=pathlib.Path,default=pathlib.Path("config/compute-guest-profiles.json"))
    a=ap.parse_args()
    try:
        result=validate(load(a.profile))
    except (ProfileError,OSError,json.JSONDecodeError) as exc:
        print(json.dumps({"status":"ERROR","error":str(exc)},sort_keys=True))
        return 2
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0
if __name__=="__main__":
    raise SystemExit(main())
