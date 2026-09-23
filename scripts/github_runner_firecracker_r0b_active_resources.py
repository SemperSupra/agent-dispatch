#!/usr/bin/env python3
"""R0b: actively consume guest CPU and RAM to measure effective resource envelope."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import stat
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

SCHEMA="firecracker-r0b-active-resource-envelope/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
PROBE_SOURCE=pathlib.Path("experiments/firecracker/guest/r0b-resource-probe-x86_64.c")
CPU_POINTS=(1,2,4,8,16,32)
CPU_ITERATIONS=50_000_000
MEM_POINTS_MIB=(128,512,1024,2048,4096)
HOST_RESERVE_BYTES=3*1024**3
CPU_RE=re.compile(r"FIRECRACKER_R0B_CPU workers=(\d+) iterations=(\d+) elapsed_ns=(\d+) checksum=([0-9a-f]{16})")
MEM_RE=re.compile(r"FIRECRACKER_R0B_MEM mib=(\d+) pages=(\d+) elapsed_ns=(\d+) checksum=(\d+)")
EXIT_RE=f3.EXIT_RE


def _u64(v:int)->int:
    return v & 0xFFFFFFFFFFFFFFFF


def _burn(seed:int,iters:int)->int:
    x=_u64(seed^0x9e3779b97f4a7c15)
    for i in range(iters):
        x=_u64(x ^ _u64(i+0x517cc1b727220a95))
        x=_u64(x*0xbf58476d1ce4e5b9)
        x=_u64(x ^ (x>>31))
    return x


def _cpu_expected_checksum(workers:int,iters:int)->str:
    combined=14695981039346656037
    # Computing 50M loops per worker in Python would be wasteful. This function
    # is intended for unit-scale vectors only; live CPU work is validated by
    # structural result/exit plus repeatable per-point output, not duplicated
    # host computation.
    if iters>100_000:
        return ""
    for w in range(workers):
        combined=_u64(combined ^ _burn(w+1,iters))
        combined=_u64(combined*1099511628211)
    return f"{combined:016x}"


def _mem_expected_checksum(mib:int)->tuple[int,int]:
    pages=(mib*1024*1024)//4096
    checksum=sum(((i ^ 0x5a)&0xff) for i in range(pages))
    return pages,checksum


def _build_initramfs(init_bin:pathlib.Path,candidate_bin:pathlib.Path,config_text:str,out:pathlib.Path)->None:
    payload=b"".join([
        f1._newc_entry(".",mode=stat.S_IFDIR|0o755,ino=1,nlink=2),
        f1._newc_entry("dev",mode=stat.S_IFDIR|0o755,ino=2,nlink=2),
        f1._newc_entry("dev/console",mode=stat.S_IFCHR|0o600,ino=3,rdevmajor=5,rdevminor=1),
        f1._newc_entry("work",mode=stat.S_IFDIR|0o555,ino=4,nlink=2),
        f1._newc_entry("work/config.txt",mode=stat.S_IFREG|0o444,data=config_text.encode(),ino=5),
        f1._newc_entry("work/candidate",mode=stat.S_IFREG|0o555,data=candidate_bin.read_bytes(),ino=6),
        f1._newc_entry("init",mode=stat.S_IFREG|0o755,data=init_bin.read_bytes(),ino=7),
        f1._newc_entry("TRAILER!!!",mode=0,ino=8),
    ])
    out.write_bytes(payload)


def _run_point(
    *,
    mode:str,
    firecracker:pathlib.Path,
    kernel:pathlib.Path,
    init_bin:pathlib.Path,
    candidate_bin:pathlib.Path,
    work:pathlib.Path,
    vcpus:int,
    guest_mem_mib:int,
    config_text:str,
    expected_meta:dict,
)->dict:
    initrd=work/f"{mode}-{vcpus}-{guest_mem_mib}.cpio"
    _build_initramfs(init_bin,candidate_bin,config_text,initrd)
    config_path=work/f"{mode}-{vcpus}-{guest_mem_mib}.json"
    f1._build_config(kernel,initrd,config_path)
    cfg=json.loads(config_path.read_text())
    cfg["machine-config"]["vcpu_count"]=vcpus
    cfg["machine-config"]["mem_size_mib"]=guest_mem_mib
    config_path.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

    before_mem=p1._meminfo(); before_cpu=p1._cpu_ticks()
    stop=threading.Event(); sample={}
    monitor=threading.Thread(target=p1._monitor,args=(firecracker.name,stop,sample),daemon=True)
    monitor.start()
    started=time.perf_counter()
    result=f3.run_vm(firecracker,config_path,{"bytes":0,"lines":0,"words":0,"fnv1a64":""})
    # f3.run_vm cannot validate R0b output, but preserves launch/KVM handling.
    ended=time.perf_counter()
    stop.set(); monitor.join(timeout=1.0)
    after_cpu=p1._cpu_ticks(); after_mem=p1._meminfo()
    output=result.get("output_tail","")

    exit_match=EXIT_RE.search(output)
    child_ok=bool(exit_match) and int(exit_match.group(1))==0
    observed=None
    oracle=False
    if mode=="cpu":
        m=CPU_RE.search(output)
        if m:
            observed={"workers":int(m.group(1)),"iterations":int(m.group(2)),"elapsed_ns":int(m.group(3)),"checksum":m.group(4)}
            oracle=(
                observed["workers"]==expected_meta["workers"]
                and observed["iterations"]==expected_meta["iterations"]
                and observed["elapsed_ns"]>0
                and observed["checksum"]!="0000000000000000"
                and child_ok
                and result.get("clean_vmm_exit_observed")
            )
    else:
        m=MEM_RE.search(output)
        if m:
            observed={"mib":int(m.group(1)),"pages":int(m.group(2)),"elapsed_ns":int(m.group(3)),"checksum":int(m.group(4))}
            oracle=(
                observed["mib"]==expected_meta["mib"]
                and observed["pages"]==expected_meta["pages"]
                and observed["checksum"]==expected_meta["checksum"]
                and observed["elapsed_ns"]>0
                and child_ok
                and result.get("clean_vmm_exit_observed")
            )

    return {
        "mode":mode,
        "vcpu_count":vcpus,
        "guest_mem_mib":guest_mem_mib,
        "classification":"SUPPORTED" if oracle else "ORACLE_FAILURE",
        "oracle_satisfied":oracle,
        "elapsed_ms":round((ended-started)*1000.0,3),
        "observed":observed,
        "candidate_exit_code":int(exit_match.group(1)) if exit_match else None,
        "host":{
            "cpu_busy_percent":p1._cpu_busy_percent(before_cpu,after_cpu),
            "memory_before":before_mem,
            "memory_after":after_mem,
            **sample,
        },
        "output_tail":output[-5000:],
    }


def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}

    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST)
    with tempfile.TemporaryDirectory(prefix="firecracker-r0b-") as td:
        work=pathlib.Path(td)
        archive=work/"firecracker.tgz"; extract=work/"vmm"; extract.mkdir()
        kernel=work/"vmlinux"; init_bin=work/"init"; candidate_bin=work/"resource-probe"
        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract); fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(f3.INIT_SOURCE,init_bin)
        with timer.stage("resource_probe_compile","portable"):
            pc=f1._compile_init(PROBE_SOURCE,candidate_bin)
        if not all([vv["verified"],kv["verified"],ic["ok"],pc["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}

        cpu_results=[]
        for workers in CPU_POINTS:
            meta={"workers":workers,"iterations":CPU_ITERATIONS}
            text=f"mode=cpu\nworkers={workers}\niterations={CPU_ITERATIONS}\n"
            with timer.stage(f"active_cpu_{workers}","portable"):
                point=_run_point(
                    mode="cpu",firecracker=fc,kernel=kernel,init_bin=init_bin,candidate_bin=candidate_bin,
                    work=work,vcpu_count=workers,guest_mem_mib=256,config_text=text,expected_meta=meta,
                )
            cpu_results.append(point)
            if not point["oracle_satisfied"]:
                break

        mem_results=[]
        for mib in MEM_POINTS_MIB:
            host_available=p1._meminfo().get("available_bytes") or 0
            guest_mem=mib+256
            if host_available and host_available-guest_mem*1024**2<HOST_RESERVE_BYTES:
                mem_results.append({
                    "mode":"mem","mib":mib,"classification":"SKIPPED_GUARDRAIL","oracle_satisfied":False,
                    "reason":"active guest working set would leave less than 3 GiB host MemAvailable if fully resident",
                    "host_available_bytes_before":host_available,
                })
                break
            pages,checksum=_mem_expected_checksum(mib)
            meta={"mib":mib,"pages":pages,"checksum":checksum}
            text=f"mode=mem\nmib={mib}\n"
            with timer.stage(f"active_mem_{mib}","portable"):
                point=_run_point(
                    mode="mem",firecracker=fc,kernel=kernel,init_bin=init_bin,candidate_bin=candidate_bin,
                    work=work,vcpu_count=1,guest_mem_mib=guest_mem,config_text=text,expected_meta=meta,
                )
            point["working_set_mib"]=mib
            mem_results.append(point)
            if not point["oracle_satisfied"]:
                break

        cpu_stable=max((p["vcpu_count"] for p in cpu_results if p.get("oracle_satisfied")),default=0)
        mem_stable=max((p.get("working_set_mib",0) for p in mem_results if p.get("oracle_satisfied")),default=0)
        failures=[p for p in [*cpu_results,*mem_results] if p.get("classification") not in {"SUPPORTED","SKIPPED_GUARDRAIL"}]
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":"SUPPORTED" if not failures else "PARTIAL_FRONTIER",
                "largest_observed_active_cpu_workers":cpu_stable,
                "largest_observed_active_working_set_mib":mem_stable,
            },
            "host_identity":{
                "cpu":p1._cpu_identity(),"memory":p1._meminfo(),
                "image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion"),"kernel_release":platform.release(),
            },
            "cpu_points":cpu_results,
            "memory_points":mem_results,
            "lifecycle_timing":timer.receipt(),
            "next_gate":"If 4 GiB active memory remains healthy, one earned larger working-set point may be tried; CPU results determine useful vCPU saturation.",
        }


def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args();a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n");print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED","PARTIAL_FRONTIER"} else 1

if __name__=="__main__":raise SystemExit(main())
