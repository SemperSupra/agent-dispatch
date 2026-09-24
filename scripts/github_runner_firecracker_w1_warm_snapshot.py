#!/usr/bin/env python3
"""W1: warm normal Ubuntu/Python userspace snapshot-resume economics on one GHA host."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_p3_same_host_handoff as p3
import github_runner_firecracker_u1_userspace as u1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-w1-warm-userspace-snapshot/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
USERSPACE_MANIFEST=pathlib.Path("experiments/firecracker/guest-userspace-ubuntu-24.04-x86_64.json")
INIT_SOURCE=pathlib.Path("experiments/firecracker/guest/w1-bridge-init-x86_64.c")
GUEST_SOURCE=pathlib.Path("experiments/firecracker/guest/w1-warm-userspace.py")
READY_RE=re.compile(r"FIRECRACKER_W1_READY counter=(\d+) python=(\S+) pid=(\d+)")
HEARTBEAT_RE=re.compile(r"FIRECRACKER_W1_HEARTBEAT counter=(\d+)")
WORK_RE=re.compile(r"FIRECRACKER_W1_WORK counter=(\d+) work_ns=(\d+) digest=([0-9a-f]{64})")
EXIT_RE=re.compile(r"FIRECRACKER_W1_EXIT code=(\d+)")
COUNTER_MAX=10
BLOCK_BYTES=1024*1024
ITERATIONS=64

def _sha256(path:pathlib.Path)->str:
    return u1._sha256(path)

def expected_digest()->str:
    block=bytes(((i*17+3)&0xff) for i in range(BLOCK_BYTES))
    h=hashlib.sha256()
    for _ in range(ITERATIONS):
        h.update(block)
    return h.hexdigest()

def _build_initramfs(init_bin:pathlib.Path,out:pathlib.Path)->None:
    import stat
    payload=b"".join([
        f1._newc_entry(".",mode=stat.S_IFDIR|0o755,ino=1,nlink=2),
        f1._newc_entry("dev",mode=stat.S_IFDIR|0o755,ino=2,nlink=2),
        f1._newc_entry("dev/console",mode=stat.S_IFCHR|0o600,ino=3,rdevmajor=5,rdevminor=1),
        f1._newc_entry("dev/vda",mode=stat.S_IFBLK|0o660,ino=4,rdevmajor=254,rdevminor=0),
        f1._newc_entry("dev/vdb",mode=stat.S_IFBLK|0o660,ino=5,rdevmajor=254,rdevminor=16),
        f1._newc_entry("newroot",mode=stat.S_IFDIR|0o755,ino=6,nlink=2),
        f1._newc_entry("init",mode=stat.S_IFREG|0o755,data=init_bin.read_bytes(),ino=7),
        f1._newc_entry("TRAILER!!!",mode=0,ino=8),
    ])
    out.write_bytes(payload)

def _debugfs_write(image:pathlib.Path,src:pathlib.Path,dst:str)->dict:
    debugfs=shutil.which("debugfs")
    if not debugfs:
        return {"ok":False,"reason":"debugfs unavailable"}
    cp=__import__("subprocess").run(
        [debugfs,"-w","-R",f"write {src.resolve()} {dst}",str(image)],
        capture_output=True,text=True,timeout=20,check=False,
    )
    return {"ok":cp.returncode==0,"stdout":cp.stdout[-2000:],"stderr":cp.stderr[-2000:]}

def _preload_scratch(image:pathlib.Path)->dict:
    return _debugfs_write(image,GUEST_SOURCE,"/w1.py")

def _inspect_scratch(image:pathlib.Path,work:pathlib.Path)->dict:
    debugfs=shutil.which("debugfs")
    if not debugfs:
        return {"ok":False,"reason":"debugfs unavailable"}
    result_file=work/"w1-result.json"
    code,out,err=f0._run([debugfs,"-R",f"dump -p /w1-result.json {result_file}",str(image)],timeout=20)
    if code!=0 or not result_file.exists():
        return {"ok":False,"reason":"result dump failed","stderr":err[-1000:] if err else ""}
    try:
        result=json.loads(result_file.read_text())
    except Exception as exc:
        return {"ok":False,"reason":f"result JSON invalid: {exc}"}
    ok=(
        result.get("counter")==COUNTER_MAX
        and result.get("digest")==expected_digest()
        and result.get("block_bytes")==BLOCK_BYTES
        and result.get("iterations")==ITERATIONS
        and isinstance(result.get("work_ns"),int) and result["work_ns"]>0
    )
    return {"ok":ok,"result":result}

def _heartbeat_values(lines:list[str])->list[int]:
    values=[]
    for line in list(lines):
        m=HEARTBEAT_RE.search(line)
        if m:
            values.append(int(m.group(1)))
    return values

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    vm=f1._load_json(f3.VMM_MANIFEST)
    km=f1._load_json(f3.KERNEL_MANIFEST)
    um=json.loads(USERSPACE_MANIFEST.read_text())
    expected=expected_digest()

    with tempfile.TemporaryDirectory(prefix="firecracker-w1-") as td:
        w=pathlib.Path(td)
        archive=w/"firecracker.tgz"; extract=w/"extract"; extract.mkdir()
        kernel=w/"vmlinux"; rootfs=w/"ubuntu.squashfs"; scratch=w/"scratch.ext4"
        init_bin=w/"init"; initrd=w/"initrd.cpio"; config_path=w/"source-config.json"
        source_sock=w/"source.sock"; dest_sock=w/"dest.sock"
        state_file=w/"snapshot.state"; mem_file=w/"snapshot.mem"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract)
            firecracker=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("userspace_download_and_verify","venue"):
            uv=f1._download_and_verify(um["rootfs_url"],um["rootfs_sha256"],rootfs)
        with timer.stage("bridge_init_compile","portable"):
            ic=f1._compile_init(INIT_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],uv["verified"],ic["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("initramfs_build","portable"):
            _build_initramfs(init_bin,initrd)
        with timer.stage("scratch_ext4_create","venue"):
            ss=u1._make_scratch(scratch)
        if not ss["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":ss["reason"]}}
        with timer.stage("warm_workload_stage","portable"):
            preload=_preload_scratch(scratch)
        if not preload["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":"scratch preload failed","preload":preload}}

        cfg=f1._build_config(kernel,initrd,config_path)
        cfg["machine-config"]["vcpu_count"]=1
        cfg["machine-config"]["mem_size_mib"]=512
        cfg["drives"]=[
            {"drive_id":"userspace","path_on_host":str(rootfs.resolve()),"is_root_device":False,"is_read_only":True},
            {"drive_id":"scratch","path_on_host":str(scratch.resolve()),"is_root_device":False,"is_read_only":False},
        ]
        cfg["network-interfaces"]=[]
        config_path.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

        root_before=_sha256(rootfs)
        source_lines=[]; source_stop=threading.Event()
        cold_started=time.perf_counter()
        with timer.stage("cold_boot_to_ready","portable"):
            source=p3._launch(firecracker,source_sock,config_path)
            source_reader=threading.Thread(target=p3._reader,args=(source,source_lines,source_stop),daemon=True)
            source_reader.start()
            if not p3._wait_for_socket(source_sock,5):
                p3._terminate_group(source)
                return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":"source API socket not ready"}}
            ready=p3._wait_for_regex(source_lines,READY_RE,8)
            if not ready:
                p3._terminate_group(source)
                return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"warm userspace READY not observed"}}
        cold_ready_ms=round((time.perf_counter()-cold_started)*1000.0,3)
        source_pid=p3._actual_firecracker_pid(source_sock)

        with timer.stage("pause_api","portable"):
            pause=p3._api(source_sock,"PATCH","/vm",{"state":"Paused"})
        if not pause["ok"]:
            p3._terminate_group(source)
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"pause failed","pause":pause}}
        time.sleep(0.03)
        source_hb=_heartbeat_values(source_lines)
        source_last_counter=max(source_hb) if source_hb else 0

        with timer.stage("snapshot_create_full","portable"):
            create=p3._api(source_sock,"PUT","/snapshot/create",{
                "snapshot_type":"Full",
                "snapshot_path":str(state_file.resolve()),
                "mem_file_path":str(mem_file.resolve()),
                "sync_snapshot_files":True,
            })
        if not create["ok"] or not state_file.exists() or not mem_file.exists():
            p3._terminate_group(source)
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"snapshot create failed","create":create}}

        with timer.stage("source_termination","portable"):
            source_term=p3._terminate_group(source)
        source_stop.set(); source_reader.join(timeout=1)
        source_pid_after=p3._actual_firecracker_pid(source_sock)

        dest_lines=[]; dest_stop=threading.Event()
        with timer.stage("destination_process_start","portable"):
            dest=p3._launch(firecracker,dest_sock,None)
            dest_reader=threading.Thread(target=p3._reader,args=(dest,dest_lines,dest_stop),daemon=True)
            dest_reader.start()
            if not p3._wait_for_socket(dest_sock,5):
                p3._terminate_group(dest)
                return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":"destination API socket not ready"}}
        dest_pid=p3._actual_firecracker_pid(dest_sock)

        warm_started=time.perf_counter()
        with timer.stage("snapshot_load","portable"):
            load=p3._api(dest_sock,"PUT","/snapshot/load",{
                "snapshot_path":str(state_file.resolve()),
                "mem_backend":{"backend_path":str(mem_file.resolve()),"backend_type":"File"},
                "track_dirty_pages":False,
                "resume_vm":False,
            })
        if not load["ok"]:
            p3._terminate_group(dest)
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"snapshot load failed","load":load}}

        resume_started=time.perf_counter()
        with timer.stage("resume_api","portable"):
            resume=p3._api(dest_sock,"PATCH","/vm",{"state":"Resumed"})
        if not resume["ok"]:
            p3._terminate_group(dest)
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"resume failed","resume":resume}}

        first_hb=p3._wait_for_regex(dest_lines,HEARTBEAT_RE,5)
        resume_to_first_output_ms=round((time.perf_counter()-resume_started)*1000.0,3) if first_hb else None
        warm_to_first_output_ms=round((time.perf_counter()-warm_started)*1000.0,3) if first_hb else None
        if resume_to_first_output_ms is not None:
            timer.add("resume_to_first_guest_output","portable",resume_to_first_output_ms,derived=True)
        if warm_to_first_output_ms is not None:
            timer.add("load_start_to_first_guest_output","portable",warm_to_first_output_ms,derived=True)

        work=p3._wait_for_regex(dest_lines,WORK_RE,8)
        try:
            dest_rc=dest.wait(timeout=5)
        except __import__("subprocess").TimeoutExpired:
            dest_rc=p3._terminate_group(dest)["return_code"]
        dest_stop.set(); dest_reader.join(timeout=1)

        dest_ready_seen=any(READY_RE.search(line) for line in dest_lines)
        dest_hb=_heartbeat_values(dest_lines)
        dest_first_counter=dest_hb[0] if dest_hb else None
        exit_values=[int(m.group(1)) for line in dest_lines if (m:=EXIT_RE.search(line))]
        work_observed=None
        if work:
            work_observed={
                "counter":int(work.group(1)),
                "work_ns":int(work.group(2)),
                "digest":work.group(3),
            }

        with timer.stage("post_vm_scratch_reconciliation","portable"):
            scratch_result=_inspect_scratch(scratch,w)
        root_after=_sha256(rootfs)
        root_immutable=root_before==root_after==um["rootfs_sha256"]

        with timer.stage("snapshot_hash_receipt","portable"):
            snapshot={
                "state_size_bytes":state_file.stat().st_size,
                "mem_size_bytes":mem_file.stat().st_size,
                "state_sha256":_sha256(state_file),
                "mem_sha256":_sha256(mem_file),
            }

        continuity_ok=(
            source_pid is not None and dest_pid is not None and source_pid!=dest_pid
            and source_pid_after is None
            and dest_first_counter is not None and dest_first_counter>source_last_counter
            and not dest_ready_seen
            and work_observed is not None
            and work_observed["counter"]==COUNTER_MAX
            and work_observed["digest"]==expected
            and bool(exit_values) and max(exit_values)==0
            and dest_rc==0
            and scratch_result["ok"]
            and root_immutable
        )
        warm_path_ms=warm_to_first_output_ms
        cold_over_warm=round(cold_ready_ms/warm_path_ms,4) if warm_path_ms else None

        return {
            "schema":SCHEMA,
            "authority":AUTHORITY,
            "requested_label":label,
            "result":{
                "classification":"SUPPORTED" if continuity_ok else "ORACLE_FAILURE",
                "warm_userspace_snapshot_supported":continuity_ok,
                "source_firecracker_pid":source_pid,
                "destination_firecracker_pid":dest_pid,
                "source_absent_before_resume":source_pid_after is None,
                "destination_reemitted_ready":dest_ready_seen,
                "source_last_heartbeat_counter":source_last_counter,
                "destination_first_heartbeat_counter":dest_first_counter,
                "destination_exit_code":dest_rc,
                "rootfs_immutable":root_immutable,
                "scratch_reconciled":scratch_result["ok"],
            },
            "timing_comparison":{
                "cold_boot_to_ready_ms":cold_ready_ms,
                "snapshot_load_ms":load.get("elapsed_ms"),
                "resume_api_ms":resume.get("elapsed_ms"),
                "resume_to_first_guest_output_ms":resume_to_first_output_ms,
                "load_start_to_first_guest_output_ms":warm_to_first_output_ms,
                "cold_ready_over_warm_first_output_ratio":cold_over_warm,
                "guest_post_resume_work_ns":work_observed["work_ns"] if work_observed else None,
            },
            "work":work_observed,
            "expected_work_digest":expected,
            "snapshot":snapshot,
            "api":{"pause":pause,"create":create,"load":load,"resume":resume,"source_termination":source_term},
            "portable":{
                "vmm_version":vm["version"],
                "kernel_version":km["kernel_version"],
                "userspace_distribution":um["distribution"],
                "userspace_version":um["distribution_version"],
                "machine":{"vcpu_count":1,"mem_size_mib":512,"drives":2,"network_interfaces":0},
            },
            "host_reconciliation":scratch_result,
            "lifecycle_timing":timer.receipt(),
            "source_output_tail":"\n".join(source_lines[-100:]),
            "destination_output_tail":"\n".join(dest_lines[-100:]),
            "interpretation_gate":"Compare warm restore availability with cold boot; jailer composition only if this materially changes short-workload placement.",
        }

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try:
        receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1

if __name__=="__main__":
    raise SystemExit(main())
