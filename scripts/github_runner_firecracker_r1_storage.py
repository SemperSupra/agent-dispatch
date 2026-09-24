#!/usr/bin/env python3
"""R1: bounded writable virtio-block scratch-storage qualification."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
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

SCHEMA="firecracker-r1-storage-envelope/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
PROBE_SOURCE=pathlib.Path("experiments/firecracker/guest/r1-storage-probe-x86_64.c")
BYTES=64*1024*1024
IMAGE_MIB=128
RESULT_RE=re.compile(
    r"FIRECRACKER_R1_STORAGE bytes=(\d+) write_fsync_ns=(\d+) read_ns=(\d+) "
    r"expected_checksum=(\d+) observed_checksum=(\d+)"
)
ERROR_RE=re.compile(r"FIRECRACKER_R1_STORAGE_ERROR code=(\d+)")

def _build_initramfs(init_bin:pathlib.Path,out:pathlib.Path)->None:
    payload=b"".join([
        f1._newc_entry(".",mode=stat.S_IFDIR|0o755,ino=1,nlink=2),
        f1._newc_entry("dev",mode=stat.S_IFDIR|0o755,ino=2,nlink=2),
        f1._newc_entry("dev/console",mode=stat.S_IFCHR|0o600,ino=3,rdevmajor=5,rdevminor=1),
        f1._newc_entry("dev/vda",mode=stat.S_IFBLK|0o660,ino=4,rdevmajor=254,rdevminor=0),
        f1._newc_entry("scratch",mode=stat.S_IFDIR|0o755,ino=5,nlink=2),
        f1._newc_entry("init",mode=stat.S_IFREG|0o755,data=init_bin.read_bytes(),ino=6),
        f1._newc_entry("TRAILER!!!",mode=0,ino=7),
    ])
    out.write_bytes(payload)

def _make_ext4(image:pathlib.Path)->dict:
    mkfs=shutil.which("mkfs.ext4")
    truncate=shutil.which("truncate")
    if not mkfs or not truncate:
        return {"ok":False,"reason":"truncate or mkfs.ext4 unavailable"}
    code,out,err=f0._run([truncate,"-s",f"{IMAGE_MIB}M",str(image)],timeout=10)
    if code!=0:
        return {"ok":False,"reason":err or out}
    code,out,err=f0._run([mkfs,"-q","-F",str(image)],timeout=30)
    return {"ok":code==0,"reason":None if code==0 else (err or out)[-2000:]}

def _post_vm_ext4(image:pathlib.Path)->dict:
    debugfs=shutil.which("debugfs")
    if not debugfs:
        return {"ok":False,"reason":"debugfs unavailable"}
    cp=subprocess.run([debugfs,"-R","stat /probe.bin",str(image)],capture_output=True,text=True,timeout=20,check=False)
    text=(cp.stdout or "")+"\n"+(cp.stderr or "")
    size=None
    m=re.search(r"Size:\s+(\d+)",text)
    if m:
        size=int(m.group(1))
    return {
        "ok":cp.returncode==0 and size==BYTES,
        "exit_code":cp.returncode,
        "size_bytes":size,
        "expected_size_bytes":BYTES,
        "output_tail":text[-3000:],
    }

def _run_point(fc:pathlib.Path,kernel:pathlib.Path,initrd:pathlib.Path,image:pathlib.Path,work:pathlib.Path)->dict:
    config_path=work/"r1-config.json"
    cfg=f1._build_config(kernel,initrd,config_path)
    cfg["machine-config"]["mem_size_mib"]=256
    cfg["drives"]=[{
        "drive_id":"scratch",
        "path_on_host":str(image.resolve()),
        "is_root_device":False,
        "is_read_only":False,
    }]
    config_path.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

    before_cpu=p1._cpu_ticks(); before_mem=p1._meminfo()
    stop=threading.Event(); sample={}
    monitor=threading.Thread(target=p1._monitor,args=(fc.name,stop,sample),daemon=True)
    monitor.start()
    started=time.perf_counter()
    execution=f3.run_vm(fc,config_path,{"bytes":0,"lines":0,"words":0,"fnv1a64":""},timeout_seconds=20)
    elapsed=round((time.perf_counter()-started)*1000.0,3)
    stop.set(); monitor.join(timeout=1.0)
    after_cpu=p1._cpu_ticks(); after_mem=p1._meminfo()

    output=execution.get("output_tail","")
    m=RESULT_RE.search(output)
    err=ERROR_RE.search(output)
    observed=None
    if m:
        observed={
            "bytes":int(m.group(1)),
            "write_fsync_ns":int(m.group(2)),
            "read_ns":int(m.group(3)),
            "expected_checksum":int(m.group(4)),
            "observed_checksum":int(m.group(5)),
        }
    guest_ok=bool(observed) and (
        observed["bytes"]==BYTES
        and observed["expected_checksum"]==observed["observed_checksum"]
        and observed["write_fsync_ns"]>0
        and observed["read_ns"]>0
        and execution.get("clean_vmm_exit_observed")
    )
    persisted=_post_vm_ext4(image)
    oracle=guest_ok and persisted["ok"]
    return {
        "classification":"SUPPORTED" if oracle else "ORACLE_FAILURE",
        "oracle_satisfied":oracle,
        "guest_oracle_satisfied":guest_ok,
        "post_vm_persistence_oracle_satisfied":persisted["ok"],
        "elapsed_ms":elapsed,
        "observed":observed,
        "guest_error_code":int(err.group(1)) if err else None,
        "post_vm_ext4":persisted,
        "host":{
            "cpu_busy_percent":p1._cpu_busy_percent(before_cpu,after_cpu),
            "memory_before":before_mem,
            "memory_after":after_mem,
            **sample,
        },
        "output_tail":output[-6000:],
    }

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}
    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST)
    with tempfile.TemporaryDirectory(prefix="firecracker-r1-") as td:
        w=pathlib.Path(td);archive=w/"firecracker.tgz";extract=w/"vmm";extract.mkdir()
        kernel=w/"vmlinux"; init_bin=w/"r1-init"; initrd=w/"r1-initrd.cpio"; image=w/"scratch.ext4"
        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract); fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("storage_probe_compile","portable"):
            pc=f1._compile_init(PROBE_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],pc["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("initramfs_build","portable"):
            _build_initramfs(init_bin,initrd)
        with timer.stage("scratch_ext4_create","venue"):
            fs=_make_ext4(image)
        if not fs["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":fs["reason"]}}
        with timer.stage("virtio_block_workload","portable"):
            point=_run_point(fc,kernel,initrd,image,w)
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":point["classification"],
                "writable_virtio_block_supported":point["oracle_satisfied"],
            },
            "point":point,
            "device":{
                "image_mib":IMAGE_MIB,
                "filesystem":"ext4",
                "attached_as":"virtio-block /dev/vda",
                "guest_write_read_bytes":BYTES,
                "network_interfaces":0,
            },
            "host_identity":{
                "cpu":p1._cpu_identity(),"memory":p1._meminfo(),
                "image_os":os.environ.get("ImageOS"),"image_version":os.environ.get("ImageVersion"),
                "kernel_release":platform.release(),
            },
            "lifecycle_timing":timer.receipt(),
            "next_gate":"If baseline storage passes, add exactly one Firecracker block rate-limit condition and compare behavior.",
        }

def main()->int:
    p=argparse.ArgumentParser();p.add_argument("--label",required=True);p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args();a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n");print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1

if __name__=="__main__":raise SystemExit(main())
