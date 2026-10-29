#!/usr/bin/env python3
"""J3: matched unjailed vs jailed Firecracker concurrency at N=1,2,4."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import pathlib
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_j1_jailed_f3 as j1
import github_runner_firecracker_p1_concurrency as p1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-j3-jailed-concurrency/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
POINTS=(1,2,4)
MANIFEST=pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")
KERNEL_MANIFEST=pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")


def _host_sample_start(firecracker_name:str):
    stop=threading.Event(); sample={}
    monitor=threading.Thread(target=p1._monitor,args=(firecracker_name,stop,sample),daemon=True)
    before_cpu=p1._cpu_ticks(); before_mem=p1._meminfo()
    monitor.start()
    return stop,sample,monitor,before_cpu,before_mem


def _host_sample_finish(state):
    stop,sample,monitor,before_cpu,before_mem=state
    stop.set();monitor.join(timeout=1.0)
    return {
        "cpu_busy_percent":p1._cpu_busy_percent(before_cpu,p1._cpu_ticks()),
        "memory_before":before_mem,
        "memory_after":p1._meminfo(),
        **sample,
    }


def _run_unjailed_point(n:int,firecracker:pathlib.Path,config:pathlib.Path,expected:dict)->dict:
    barrier=threading.Barrier(n+1)
    def worker(i:int):
        barrier.wait();start=time.perf_counter();r=f3.run_vm(firecracker,config,expected);end=time.perf_counter()
        return {"index":i,"ok":bool(r.get("ok")),"elapsed_ms":round((end-start)*1000,3),"kernel_to_init_ms":r.get("kernel_to_init_ms")}
    host=_host_sample_start(firecracker.name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures=[pool.submit(worker,i) for i in range(n)]
        start=time.perf_counter();barrier.wait();workers=[f.result() for f in futures];end=time.perf_counter()
    return {
        "kind":"unjailed","n":n,"all_oracles_satisfied":all(w["ok"] for w in workers),
        "makespan_ms":round((end-start)*1000,3),"per_vm":workers,"host":_host_sample_finish(host),
    }


def _run_jailed_point(
    n:int,
    *,
    jailer:pathlib.Path,
    firecracker:pathlib.Path,
    jail_base:pathlib.Path,
    identities:list[dict],
    kernel:pathlib.Path,
    initrd:pathlib.Path,
    expected:dict,
)->dict:
    barrier=threading.Barrier(n+1)
    vm_ids=[]
    for i in range(n):
        vm_id=f"j3-n{n}-i{i}-{os.getpid()}"
        vm_ids.append(vm_id)
        jail_root=jail_base/firecracker.name/vm_id/"root"
        cfg={
            "boot-source":{"kernel_image_path":"/vmlinux","initrd_path":"/initrd.cpio","boot_args":"console=ttyS0 reboot=k panic=1 pci=off"},
            "drives":[],
            "machine-config":{"vcpu_count":1,"mem_size_mib":128,"smt":False,"track_dirty_pages":False,"huge_pages":"None"},
            "network-interfaces":[],
        }
        j1._stage_jail_files(jail_root,kernel,initrd,cfg,identities[i]["uid"],identities[i]["gid"])

    def worker(i:int):
        barrier.wait()
        return j1._run_jailed(
            jailer,firecracker,jail_base,vm_ids[i],
            identities[i]["uid"],identities[i]["gid"],expected,
        )

    host=_host_sample_start(firecracker.name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        futures=[pool.submit(worker,i) for i in range(n)]
        start=time.perf_counter();barrier.wait();workers=[f.result() for f in futures];end=time.perf_counter()
    simplified=[]
    for i,r in enumerate(workers):
        obs=r.get("process_observation") or {}
        simplified.append({
            "index":i,"ok":bool(r.get("ok")),"elapsed_ms":r.get("elapsed_ms"),
            "kernel_to_init_ms":r.get("kernel_to_init_ms"),
            "uid_drop_observed":bool(obs.get("uid_fields") and obs["uid_fields"][0]==identities[i]["uid"]),
            "gid_drop_observed":bool(obs.get("gid_fields") and obs["gid_fields"][0]==identities[i]["gid"]),
            "seccomp_mode":obs.get("seccomp_mode"),
            "mnt_ns":obs.get("mnt_ns"),
        })
    return {
        "kind":"jailed","n":n,
        "all_oracles_satisfied":all(x["ok"] for x in simplified),
        "all_uid_gid_seccomp_satisfied":all(x["uid_drop_observed"] and x["gid_drop_observed"] and x["seccomp_mode"]==2 for x in simplified),
        "makespan_ms":round((end-start)*1000,3),"per_vm":simplified,"host":_host_sample_finish(host),
    }


def run_probe(label:str)->dict:
    timer=LifecycleTimer();vm=json.loads(MANIFEST.read_text());km=json.loads(KERNEL_MANIFEST.read_text())
    data=f3.DEFAULT_INPUT.read_bytes();expected=f3.expected_result(data)
    identities=[];trusted_base=pathlib.Path(f"/opt/agent-dispatch-fcj3-{os.getpid()}")
    with tempfile.TemporaryDirectory(prefix="firecracker-j3-") as td:
        w=pathlib.Path(td);archive=w/"firecracker.tgz";extract=w/"extract";extract.mkdir()
        kernel=w/"vmlinux";init_bin=w/"init";cand_bin=w/"candidate";initrd=w/"initrd.cpio";config_path=w/"unjailed.json"
        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("archive_extract","portable"):
            f0._safe_extract(archive,extract)
            firecracker=j1._find_binary(extract,f"firecracker-{vm['version']}-{vm['architecture']}")
            jailer=j1._find_binary(extract,f"jailer-{vm['version']}-{vm['architecture']}")
            firecracker.chmod(firecracker.stat().st_mode|0o111);jailer.chmod(jailer.stat().st_mode|0o111)
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("candidate_compile","portable"):
            cc=f1._compile_init(f3.CANDIDATE_SOURCE,cand_bin)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(f3.INIT_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],cc["ok"],ic["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("capsule_build","portable"):
            f3.build_initramfs(init_bin,cand_bin,data,initrd)
            f1._build_config(kernel,initrd,config_path)

        with timer.stage("ephemeral_identities_create","venue"):
            for i in range(max(POINTS)):
                identities.append(j1._create_ephemeral_identity(f"fcj3{os.getpid()}i{i}"))
        try:
            with timer.stage("trusted_runtime_stage","venue"):
                trusted=j1._stage_trusted_runtime(trusted_base,firecracker,jailer)

            results=[]
            for n in POINTS:
                with timer.stage(f"unjailed_n{n}","portable"):
                    u=_run_unjailed_point(n,firecracker,config_path,expected)
                with timer.stage(f"jailed_n{n}","portable"):
                    j=_run_jailed_point(
                        n,jailer=trusted["jailer"],firecracker=trusted["firecracker"],jail_base=trusted["jail_base"],
                        identities=identities,kernel=kernel,initrd=initrd,expected=expected,
                    )
                ratio=round(j["makespan_ms"]/u["makespan_ms"],4) if u["makespan_ms"] else None
                results.append({"n":n,"unjailed":u,"jailed":j,"jailed_over_unjailed_makespan_ratio":ratio,"delta_ms":round(j["makespan_ms"]-u["makespan_ms"],3)})
        finally:
            with timer.stage("jail_cleanup","venue"):
                j1._sudo(["rm","-rf",str(trusted_base)])
            with timer.stage("identities_cleanup","venue"):
                cleanup=[j1._delete_ephemeral_identity(x) for x in identities]

        ok=all(x["unjailed"]["all_oracles_satisfied"] and x["jailed"]["all_oracles_satisfied"] and x["jailed"]["all_uid_gid_seccomp_satisfied"] for x in results)
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{"classification":"SUPPORTED" if ok else "PARTIAL","all_points_passed":ok},
            "points":results,"identity_cleanup":cleanup,
            "host_identity":{"cpu":p1._cpu_identity(),"memory":p1._meminfo(),"image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion")},
            "lifecycle_timing":timer.receipt(),
            "next_gate":"Use matched J3 observations to decide whether jailer overhead changes placement/concurrency policy.",
        }


def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args();a.out.parent.mkdir(parents=True,exist_ok=True)
    try:receipt=run_probe(a.label)
    except Exception as exc:receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n");print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED","PARTIAL"} else 1

if __name__=="__main__":raise SystemExit(main())
