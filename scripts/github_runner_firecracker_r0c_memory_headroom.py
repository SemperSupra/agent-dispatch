#!/usr/bin/env python3
"""R0c: refine active-memory frontier with explicit guest-memory headroom."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p1_concurrency as p1
import github_runner_firecracker_r0b_active_resources as r0b
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-r0c-active-memory-headroom/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
POINTS_MIB=(4096,6144)
GUEST_HEADROOM_MIB=1024
HOST_RESERVE_BYTES=3*1024**3


def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}
    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST)
    with tempfile.TemporaryDirectory(prefix="firecracker-r0c-") as td:
        work=pathlib.Path(td);archive=work/"firecracker.tgz";extract=work/"vmm";extract.mkdir()
        kernel=work/"vmlinux";init_bin=work/"init";candidate_bin=work/"resource-probe"
        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract);fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(f3.INIT_SOURCE,init_bin)
        with timer.stage("resource_probe_compile","portable"):
            pc=f1._compile_init(r0b.PROBE_SOURCE,candidate_bin)
        if not all([vv["verified"],kv["verified"],ic["ok"],pc["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}

        results=[]
        for mib in POINTS_MIB:
            guest_mem=mib+GUEST_HEADROOM_MIB
            available=p1._meminfo().get("available_bytes") or 0
            if available and available-guest_mem*1024**2<HOST_RESERVE_BYTES:
                results.append({
                    "working_set_mib":mib,"guest_mem_mib":guest_mem,
                    "classification":"SKIPPED_GUARDRAIL","oracle_satisfied":False,
                    "host_available_bytes_before":available,
                    "reason":"would leave less than 3 GiB host MemAvailable if fully resident",
                })
                break
            pages,checksum=r0b._mem_expected_checksum(mib)
            meta={"mib":mib,"pages":pages,"checksum":checksum}
            cfg=f"mode=mem\nmib={mib}\n"
            with timer.stage(f"active_mem_{mib}","portable"):
                point=r0b._run_point(
                    mode="mem",firecracker=fc,kernel=kernel,init_bin=init_bin,candidate_bin=candidate_bin,
                    work=work,vcpus=1,guest_mem_mib=guest_mem,config_text=cfg,expected_meta=meta,
                )
            point["working_set_mib"]=mib
            results.append(point)
            if not point["oracle_satisfied"]:
                break

        stable=max((p.get("working_set_mib",0) for p in results if p.get("oracle_satisfied")),default=0)
        failures=[p for p in results if p.get("classification") not in {"SUPPORTED","SKIPPED_GUARDRAIL"}]
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":"SUPPORTED" if not failures else "PARTIAL_FRONTIER",
                "largest_observed_active_working_set_mib":stable,
                "guest_headroom_mib":GUEST_HEADROOM_MIB,
            },
            "points":results,
            "host_identity":{"cpu":p1._cpu_identity(),"memory":p1._meminfo(),"image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},
            "lifecycle_timing":timer.receipt(),
            "next_gate":"If 6 GiB passes with comfortable host reserve, one final bounded 8 GiB active-working-set point may be earned.",
        }


def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args();a.out.parent.mkdir(parents=True,exist_ok=True)
    try:receipt=run_probe(a.label)
    except Exception as exc:receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n");print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED","PARTIAL_FRONTIER"} else 1

if __name__=="__main__":raise SystemExit(main())
