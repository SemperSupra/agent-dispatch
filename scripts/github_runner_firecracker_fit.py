#!/usr/bin/env python3
"""Firecracker-specific GitHub-hosted runner fit probe."""
from __future__ import annotations

import argparse, json, os, pathlib, platform, shutil, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f3_useful_work as f3

SCHEMA="firecracker-gha-runner-fit/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"

def _kvm_observation():
    user=f0._kvm_user_probe()
    sudo=f0._kvm_sudo_probe() if user.get("present") else {
        "available":bool(shutil.which("sudo")),
        "callable":False,
        "api_version":None,
        "error":"KVM absent; sudo KVM probe not attempted",
    }
    return {"user":user,"sudo":sudo}

def run_probe(label:str,mode:str)->dict:
    arch=platform.machine()
    system=platform.system()
    kvm=_kvm_observation() if system=="Linux" else {"user":{},"sudo":{}}
    kvm_callable=bool(kvm["user"].get("callable") or kvm["sudo"].get("callable"))
    base={
        "schema":SCHEMA,
        "authority":AUTHORITY,
        "requested_label":label,
        "mode":mode,
        "platform":{
            "system":system,
            "architecture":arch,
            "kernel_release":platform.release(),
            "image_os":os.environ.get("ImageOS"),
            "image_version":os.environ.get("ImageVersion"),
            "logical_cpus":os.cpu_count(),
        },
        "kvm":kvm,
    }

    if mode=="preflight":
        if system!="Linux":
            classification="UNSUPPORTED_HOST_OS"
            reason="Firecracker requires Linux/KVM"
        elif not kvm["user"].get("present"):
            classification="BLOCKED_NO_KVM"
            reason="/dev/kvm not observed"
        elif not kvm_callable:
            classification="BLOCKED_KVM_NOT_CALLABLE"
            reason="/dev/kvm observed but no qualified KVM access path"
        else:
            classification="KVM_PREREQUISITE_SUPPORTED"
            reason="KVM prerequisite available; Firecracker guest not exercised in this preflight mode"
        base["result"]={
            "classification":classification,
            "reason":reason,
            "firecracker_guest_exercised":False,
        }
        return base

    if system!="Linux" or arch not in {"x86_64","amd64"}:
        base["result"]={
            "classification":"UNSUPPORTED_FOR_CURRENT_FULL_PROBE",
            "reason":"current pinned full-probe artifacts are x86_64 Linux",
            "firecracker_guest_exercised":False,
        }
        return base
    if not kvm_callable:
        base["result"]={
            "classification":"BLOCKED_KVM_PREREQUISITE",
            "reason":"full Firecracker probe requires callable KVM",
            "firecracker_guest_exercised":False,
        }
        return base

    receipt=f3.run_probe(label,f3.DEFAULT_INPUT)
    ok=receipt.get("result",{}).get("classification")=="SUPPORTED"
    base["result"]={
        "classification":"SUPPORTED" if ok else "FIRECRACKER_PROBE_FAILED",
        "reason":"fixed F3 useful-work capsule passed" if ok else "F3 useful-work capsule did not pass",
        "firecracker_guest_exercised":True,
    }
    base["f3_receipt"]=receipt
    return base

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--label",required=True)
    p.add_argument("--mode",choices=("full","preflight"),required=True)
    p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label,a.mode)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    # Negative prerequisite observations are valid census results, not CI failures.
    return 1 if receipt["result"]["classification"]=="HARNESS_FAILURE" else 0

if __name__=="__main__": raise SystemExit(main())
