#!/usr/bin/env python3
"""U1: pinned normal Ubuntu userspace + Python + writable scratch inside Firecracker."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import firecracker_execution_adapter as exec_adapter
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_r1_storage as r1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-u1-normal-userspace/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
USERSPACE_MANIFEST=pathlib.Path("experiments/firecracker/guest-userspace-ubuntu-24.04-x86_64.json")
INIT_SOURCE=pathlib.Path("experiments/firecracker/guest/u1-bridge-init-x86_64.c")
PROBE_SOURCE=pathlib.Path("experiments/firecracker/guest/u1-userspace-probe.py")
PAYLOAD=b"firecracker-u1-normal-userspace\n"
PAYLOAD_SHA256=hashlib.sha256(PAYLOAD).hexdigest()
U1_RE=re.compile(
    r"FIRECRACKER_U1_USERSPACE os_id=(\S+) os_version=(\S+) python=(\S+) "
    r"arch=(\S+) shell=(\d+) tools=(\S+) scratch_sha256=([0-9a-f]{64})"
)
EXIT_RE=re.compile(r"FIRECRACKER_U1_EXIT code=(\d+)")

def _sha256(path:pathlib.Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def _build_initramfs(init_bin:pathlib.Path,probe_source:pathlib.Path,out:pathlib.Path)->None:
    payload=b"".join([
        f1._newc_entry(".",mode=stat.S_IFDIR|0o755,ino=1,nlink=2),
        f1._newc_entry("dev",mode=stat.S_IFDIR|0o755,ino=2,nlink=2),
        f1._newc_entry("dev/console",mode=stat.S_IFCHR|0o600,ino=3,rdevmajor=5,rdevminor=1),
        f1._newc_entry("dev/vda",mode=stat.S_IFBLK|0o660,ino=4,rdevmajor=254,rdevminor=0),
        f1._newc_entry("dev/vdb",mode=stat.S_IFBLK|0o660,ino=5,rdevmajor=254,rdevminor=16),
        f1._newc_entry("newroot",mode=stat.S_IFDIR|0o755,ino=6,nlink=2),
        f1._newc_entry("work",mode=stat.S_IFDIR|0o755,ino=7,nlink=2),
        f1._newc_entry("work/u1.py",mode=stat.S_IFREG|0o444,data=probe_source.read_bytes(),ino=8),
        f1._newc_entry("init",mode=stat.S_IFREG|0o755,data=init_bin.read_bytes(),ino=9),
        f1._newc_entry("TRAILER!!!",mode=0,ino=10),
    ])
    out.write_bytes(payload)

def _make_scratch(image:pathlib.Path)->dict:
    truncate=shutil.which("truncate"); mkfs=shutil.which("mkfs.ext4")
    if not truncate or not mkfs:
        return {"ok":False,"reason":"truncate or mkfs.ext4 unavailable"}
    code,out,err=f0._run([truncate,"-s","256M",str(image)],timeout=10)
    if code!=0: return {"ok":False,"reason":err or out}
    code,out,err=f0._run([mkfs,"-q","-F",str(image)],timeout=30)
    return {"ok":code==0,"reason":None if code==0 else (err or out)[-2000:]}

def _run_vm(fc:pathlib.Path,config:pathlib.Path,timeout_seconds:int=30)->dict:
    timeout=shutil.which("timeout")
    access=exec_adapter.select_kvm_access()
    if not timeout or access.get("classification")!="SUPPORTED":
        return {"ok":False,"classification":"SETUP_REQUIRED","reason":"timeout or KVM boundary unavailable"}
    command=exec_adapter.privileged_command(
        [timeout,"--signal=TERM","--kill-after=2s",f"{timeout_seconds}s",
         str(fc.resolve()),"--no-api","--config-file",str(config.resolve())],
        access,
    )
    started=time.perf_counter()
    code,out,err=f0._run(command,timeout=timeout_seconds+5)
    elapsed=round((time.perf_counter()-started)*1000.0,3)
    combined="\n".join(x for x in (out,err) if x)
    um=U1_RE.search(combined); em=EXIT_RE.search(combined)
    observed=None
    if um:
        tools={}
        for item in um.group(6).split(","):
            name,value=item.split(":",1)
            tools[name]=value=="1"
        observed={
            "os_id":um.group(1),
            "os_version":um.group(2),
            "python_version":um.group(3),
            "architecture":um.group(4),
            "shell_ok":um.group(5)=="1",
            "tools":tools,
            "scratch_sha256":um.group(7),
        }
    exit_code=int(em.group(1)) if em else None
    clean=code==0 and "Firecracker exiting successfully" in combined
    oracle=bool(observed) and (
        observed["os_id"]=="ubuntu"
        and observed["os_version"]=="24.04"
        and observed["architecture"]=="x86_64"
        and observed["shell_ok"]
        and all(observed["tools"].get(t,False) for t in ("curl","fio","ip","strace"))
        and observed["scratch_sha256"]==PAYLOAD_SHA256
        and exit_code==0
        and clean
    )
    return {
        "ok":oracle,
        "classification":"SUPPORTED" if oracle else "ORACLE_FAILURE",
        "elapsed_ms":elapsed,
        "return_code":code,
        "u1_exit_code":exit_code,
        "observed":observed,
        "clean_vmm_exit_observed":clean,
        "kvm_access_mode":access.get("mode"),
        "output_tail":combined[-10000:],
    }

def _inspect_scratch(image:pathlib.Path,work:pathlib.Path)->dict:
    debugfs=shutil.which("debugfs")
    if not debugfs:
        return {"ok":False,"reason":"debugfs unavailable"}
    result_file=work/"host-u1-result.json"
    payload_file=work/"host-u1-payload.bin"
    observations={}
    for guest,host in [
        ("/u1-result.json",result_file),
        ("/u1-payload.bin",payload_file),
    ]:
        code,out,err=f0._run([debugfs,"-R",f"dump -p {guest} {host}",str(image)],timeout=20)
        observations[guest]={"exit_code":code,"stderr":err[-1000:] if err else ""}
        if code!=0 or not host.exists():
            return {"ok":False,"reason":f"debugfs dump failed for {guest}","observations":observations}
    try:
        result=json.loads(result_file.read_text())
    except Exception as exc:
        return {"ok":False,"reason":f"result JSON invalid: {exc}","observations":observations}
    payload_sha=_sha256(payload_file)
    ok=(
        result.get("os_id")=="ubuntu"
        and result.get("os_version")=="24.04"
        and result.get("architecture")=="x86_64"
        and result.get("shell_ok") is True
        and all((result.get("tools") or {}).get(t) is True for t in ("curl","fio","ip","strace"))
        and result.get("payload_sha256")==PAYLOAD_SHA256
        and payload_sha==PAYLOAD_SHA256
        and payload_file.stat().st_size==len(PAYLOAD)
    )
    return {
        "ok":ok,
        "result":result,
        "payload_sha256":payload_sha,
        "payload_size_bytes":payload_file.stat().st_size,
        "observations":observations,
    }

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}

    vm=f1._load_json(f3.VMM_MANIFEST)
    km=f1._load_json(f3.KERNEL_MANIFEST)
    um=json.loads(USERSPACE_MANIFEST.read_text())

    with tempfile.TemporaryDirectory(prefix="firecracker-u1-") as td:
        w=pathlib.Path(td)
        archive=w/"firecracker.tgz"; extract=w/"vmm"; extract.mkdir()
        kernel=w/"vmlinux"; rootfs=w/"ubuntu.squashfs"; scratch=w/"scratch.ext4"
        init_bin=w/"init"; initrd=w/"initrd.cpio"; config=w/"vm.json"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract)
            fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("userspace_download_and_verify","venue"):
            uv=f1._download_and_verify(um["rootfs_url"],um["rootfs_sha256"],rootfs)
        with timer.stage("bridge_init_compile","portable"):
            ic=f1._compile_init(INIT_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],uv["verified"],ic["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}

        with timer.stage("initramfs_build","portable"):
            _build_initramfs(init_bin,PROBE_SOURCE,initrd)
        with timer.stage("scratch_ext4_create","venue"):
            scratch_setup=_make_scratch(scratch)
        if not scratch_setup["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":scratch_setup["reason"]}}

        cfg=f1._build_config(kernel,initrd,config)
        cfg["machine-config"]["vcpu_count"]=1
        cfg["machine-config"]["mem_size_mib"]=512
        cfg["drives"]=[
            {
                "drive_id":"userspace",
                "path_on_host":str(rootfs.resolve()),
                "is_root_device":False,
                "is_read_only":True,
            },
            {
                "drive_id":"scratch",
                "path_on_host":str(scratch.resolve()),
                "is_root_device":False,
                "is_read_only":False,
            },
        ]
        config.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")
        rootfs_sha_before=_sha256(rootfs)

        with timer.stage("normal_userspace_guest_lifecycle","portable"):
            execution=_run_vm(fc,config)
        with timer.stage("post_vm_scratch_reconciliation","portable"):
            scratch_result=_inspect_scratch(scratch,w)
        rootfs_sha_after=_sha256(rootfs)
        rootfs_immutable=rootfs_sha_before==rootfs_sha_after==um["rootfs_sha256"]

        supported=execution["ok"] and scratch_result["ok"] and rootfs_immutable
        return {
            "schema":SCHEMA,
            "authority":AUTHORITY,
            "requested_label":label,
            "result":{
                "classification":"SUPPORTED" if supported else "ORACLE_FAILURE",
                "normal_userspace_supported":supported,
                "read_only_rootfs_unchanged":rootfs_immutable,
                "writable_scratch_reconciled":scratch_result["ok"],
            },
            "portable":{
                "vmm":{"version":vm["version"],"sha256":vv["actual_sha256"]},
                "kernel":{"version":km["kernel_version"],"sha256":kv["actual_sha256"]},
                "userspace":{
                    "distribution":um["distribution"],
                    "version":um["distribution_version"],
                    "format":um["rootfs_format"],
                    "sha256_before":rootfs_sha_before,
                    "sha256_after":rootfs_sha_after,
                    "size_bytes":rootfs.stat().st_size,
                },
                "machine":{
                    "vcpu_count":1,
                    "mem_size_mib":512,
                    "drives":2,
                    "network_interfaces":0,
                },
            },
            "execution":execution,
            "host_reconciliation":scratch_result,
            "lifecycle_timing":timer.receipt(),
            "next_gate":"Compose normal userspace with qualified R2 networking and jailer; then evaluate guest-side harness -> narrow inference endpoint.",
        }

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1

if __name__=="__main__": raise SystemExit(main())
