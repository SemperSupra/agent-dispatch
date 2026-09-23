#!/usr/bin/env python3
"""R0d: one final earned 8 GiB active-working-set point."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p1_concurrency as p1
import github_runner_firecracker_r0b_active_resources as r0b
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-r0d-active-memory-8g/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
WORKING_SET_MIB=8192
GUEST_MEM_MIB=9216
HOST_RESERVE_BYTES=3*1024**3

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}
    available=p1._meminfo().get("available_bytes") or 0
    if available and available-GUEST_MEM_MIB*1024**2<HOST_RESERVE_BYTES:
        return {
            "schema":SCHEMA,"authority":AUTHORITY,
            "result":{"classification":"SKIPPED_GUARDRAIL","reason":"9 GiB guest would leave less than 3 GiB host MemAvailable if fully resident"},
            "host_available_bytes_before":available,
        }
    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST)
    with tempfile.TemporaryDirectory(prefix="firecracker-r0d-") as td:
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
        pages,checksum=r0b._mem_expected_checksum(WORKING_SET_MIB)
        meta={"mib":WORKING_SET_MIB,"pages":pages,"checksum":checksum}
        with timer.stage("active_mem_8192","portable"):
            point=r0b._run_point(
                mode="mem",firecracker=fc,kernel=kernel,init_bin=init_bin,candidate_bin=candidate_bin,
                work=work,vcpus=1,guest_mem_mib=GUEST_MEM_MIB,config_text=f"mode=mem\nmib={WORKING_SET_MIB}\n",expected_meta=meta,
            )
        point["working_set_mib"]=WORKING_SET_MIB
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":point["classification"],
                "active_8g_working_set_supported":point["oracle_satisfied"],
                "stop_memory_expansion_after_this_point":True,
            },
            "point":point,
            "host_identity":{"cpu":p1._cpu_identity(),"memory":p1._meminfo(),"image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},
            "lifecycle_timing":timer.receipt(),
            "next_gate":"Stop RAM expansion. Continue to storage/network capability.",
        }

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args();a.out.parent.mkdir(parents=True,exist_ok=True)
    try:receipt=run_probe(a.label)
    except Exception as exc:receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n");print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED","SKIPPED_GUARDRAIL"} else 1

if __name__=="__main__":raise SystemExit(main())
