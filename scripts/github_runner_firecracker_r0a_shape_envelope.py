#!/usr/bin/env python3
"""R0a: bounded Firecracker guest vCPU/RAM shape envelope using fixed F3 work."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p1_concurrency as p1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-r0a-shape-envelope/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
VCPU_POINTS=(1,2,4,8,16,32)
MEM_POINTS_MIB=(128,256,512,1024,2048,4096,8192)
MIN_HOST_AVAILABLE_AFTER_RESERVATION_BYTES=2*1024**3


def _run_point(
    *,
    name:str,
    firecracker:pathlib.Path,
    kernel:pathlib.Path,
    initrd:pathlib.Path,
    vcpu_count:int,
    mem_mib:int,
    expected:dict,
    work:pathlib.Path,
)->dict:
    config_path=work/f"{name}.json"
    config={
        "boot-source":{
            "kernel_image_path":str(kernel.resolve()),
            "initrd_path":str(initrd.resolve()),
            "boot_args":"console=ttyS0 reboot=k panic=1 pci=off",
        },
        "drives":[],
        "machine-config":{
            "vcpu_count":vcpu_count,
            "mem_size_mib":mem_mib,
            "smt":False,
            "track_dirty_pages":False,
            "huge_pages":"None",
        },
        "network-interfaces":[],
    }
    config_path.write_text(json.dumps(config,indent=2,sort_keys=True)+"\n")

    mem_before=p1._meminfo()
    cpu_before=p1._cpu_ticks()
    stop=threading.Event()
    sample={}
    monitor=threading.Thread(target=p1._monitor,args=(firecracker.name,stop,sample),daemon=True)
    monitor.start()
    started=time.perf_counter()
    result=f3.run_vm(firecracker,config_path,expected)
    ended=time.perf_counter()
    stop.set(); monitor.join(timeout=1.0)
    cpu_after=p1._cpu_ticks()
    mem_after=p1._meminfo()

    return {
        "name":name,
        "vcpu_count":vcpu_count,
        "mem_size_mib":mem_mib,
        "classification":result.get("classification"),
        "oracle_satisfied":bool(result.get("ok")),
        "elapsed_ms":round((ended-started)*1000.0,3),
        "kernel_to_init_ms":result.get("kernel_to_init_ms"),
        "candidate_result":result.get("candidate_result"),
        "candidate_exit":result.get("candidate_exit"),
        "host":{
            "cpu_busy_percent":p1._cpu_busy_percent(cpu_before,cpu_after),
            "memory_before":mem_before,
            "memory_after":mem_after,
            **sample,
        },
        "output_tail":result.get("output_tail","")[-4000:],
    }


def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}

    data=f3.DEFAULT_INPUT.read_bytes()
    expected=f3.expected_result(data)
    vm=f1._load_json(f3.VMM_MANIFEST)
    km=f1._load_json(f3.KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-r0a-") as td:
        work=pathlib.Path(td)
        archive=work/"firecracker.tgz"; extract=work/"vmm"; extract.mkdir()
        kernel=work/"vmlinux"; init_bin=work/"init"; cand_bin=work/"candidate"; initrd=work/"initrd.cpio"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract)
            fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("candidate_compile","portable"):
            cc=f1._compile_init(f3.CANDIDATE_SOURCE,cand_bin)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(f3.INIT_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],cc["ok"],ic["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("capsule_initramfs_build","portable"):
            f3.build_initramfs(init_bin,cand_bin,data,initrd)

        vcpu_results=[]
        for vcpus in VCPU_POINTS:
            with timer.stage(f"vcpu_{vcpus}","portable"):
                point=_run_point(
                    name=f"vcpu-{vcpus}",firecracker=fc,kernel=kernel,initrd=initrd,
                    vcpu_count=vcpus,mem_mib=128,expected=expected,work=work,
                )
            vcpu_results.append(point)
            if not point["oracle_satisfied"]:
                break

        mem_results=[]
        for mem_mib in MEM_POINTS_MIB:
            available=(p1._meminfo().get("available_bytes") or 0)
            configured=mem_mib*1024**2
            if available and available-configured<MIN_HOST_AVAILABLE_AFTER_RESERVATION_BYTES:
                mem_results.append({
                    "name":f"mem-{mem_mib}",
                    "vcpu_count":1,
                    "mem_size_mib":mem_mib,
                    "classification":"SKIPPED_GUARDRAIL",
                    "oracle_satisfied":False,
                    "reason":"configured guest memory would leave less than 2 GiB host MemAvailable if fully committed",
                    "host_available_bytes_before":available,
                })
                break
            with timer.stage(f"mem_{mem_mib}","portable"):
                point=_run_point(
                    name=f"mem-{mem_mib}",firecracker=fc,kernel=kernel,initrd=initrd,
                    vcpu_count=1,mem_mib=mem_mib,expected=expected,work=work,
                )
            mem_results.append(point)
            if not point["oracle_satisfied"]:
                break

        vcpu_stable=max((p["vcpu_count"] for p in vcpu_results if p.get("oracle_satisfied")),default=0)
        mem_stable=max((p["mem_size_mib"] for p in mem_results if p.get("oracle_satisfied")),default=0)
        failures=[p for p in [*vcpu_results,*mem_results] if p.get("classification") not in {"SUPPORTED","SKIPPED_GUARDRAIL"}]
        classification="SUPPORTED" if not failures else "PARTIAL_FRONTIER"

        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":classification,
                "largest_observed_stable_vcpu_count":vcpu_stable,
                "largest_observed_stable_mem_mib":mem_stable,
                "note":"Shape/configuration envelope only; R0b will actively consume CPU/RAM.",
            },
            "host_identity":{
                "cpu":p1._cpu_identity(),
                "memory":p1._meminfo(),
                "image_os":os.environ.get("ImageOS"),
                "image_version":os.environ.get("ImageVersion"),
                "kernel_release":platform.release(),
            },
            "fixed_capsule":{
                "input_sha256":f3.sha256_bytes(data),
                "candidate_binary_sha256":f1._sha256(cand_bin),
                "guest_init_binary_sha256":f1._sha256(init_bin),
                "initrd_sha256":f1._sha256(initrd),
                "vmm_version":vm["version"],
                "kernel_version":km["kernel_version"],
                "network_interfaces":0,
                "drives":0,
            },
            "vcpu_points":vcpu_results,
            "memory_points":mem_results,
            "lifecycle_timing":timer.receipt(),
            "next_gate":"R0b active CPU/RAM consumption; do not interpret configured shape as useful throughput.",
        }


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED","PARTIAL_FRONTIER"} else 1

if __name__=="__main__": raise SystemExit(main())
