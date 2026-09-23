#!/usr/bin/env python3
"""P4 producer: create a device-free Firecracker snapshot bundle on one GHA runner."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_p3_same_host_handoff as p3
from firecracker_host_fingerprint import fingerprint
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-p4-producer/v1"


def run(out_dir: pathlib.Path) -> dict:
    timer=LifecycleTimer()
    out_dir.mkdir(parents=True,exist_ok=True)
    vm=f1._load_json(p3.VMM_MANIFEST)
    km=f1._load_json(p3.KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-p4-producer-") as td:
        w=pathlib.Path(td)
        archive,kernel=w/"firecracker.tgz",w/"vmlinux"
        extract=w/"vmm"; extract.mkdir()
        init_bin,initrd,config_path=w/"init",w/"initrd.cpio",w/"source-config.json"
        source_sock=w/"source.sock"
        state_file=out_dir/"snapshot.state"
        mem_file=out_dir/"snapshot.mem"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract)
            fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(p3.INIT_SOURCE,init_bin)
        if not vv["verified"] or not kv["verified"] or not ic["ok"]:
            return {"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":"artifact/build precondition failed"}}
        with timer.stage("initramfs_build","portable"):
            p3._build_initramfs(init_bin,initrd)
        with timer.stage("vm_config_build","portable"):
            config=f1._build_config(kernel,initrd,config_path)

        lines=[]
        stop=threading.Event()
        with timer.stage("source_start_to_ready","portable"):
            proc=p3._launch(fc,source_sock,config_path)
            reader=threading.Thread(target=p3._reader,args=(proc,lines,stop),daemon=True); reader.start()
            if not p3._wait_for_socket(source_sock,5):
                p3._terminate_group(proc); return {"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":"API socket unavailable"}}
            ready=p3._wait_for_regex(lines,p3.READY_RE,5)
            hb=p3._wait_for_regex(lines,p3.HEARTBEAT_RE,5)
            if not ready or not hb:
                p3._terminate_group(proc); return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"READY/heartbeat absent"}}

        source_pid=p3._actual_firecracker_pid(source_sock)
        with timer.stage("pause_api","portable"):
            pause=p3._api(source_sock,"PATCH","/vm",{"state":"Paused"})
        time.sleep(0.05)
        vals=p3._all_heartbeat_values(lines)
        last=max(vals) if vals else None
        if not pause["ok"] or last is None:
            p3._terminate_group(proc); return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"pause/counter failed"}}

        with timer.stage("snapshot_create_full","portable"):
            create=p3._api(source_sock,"PUT","/snapshot/create",{
                "snapshot_type":"Full",
                "snapshot_path":str(state_file.resolve()),
                "mem_file_path":str(mem_file.resolve()),
                "sync_snapshot_files":True,
            })
        if not create["ok"] or not state_file.exists() or not mem_file.exists():
            p3._terminate_group(proc); return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"snapshot create failed","create":create}}

        with timer.stage("source_termination","portable"):
            term=p3._terminate_group(proc)
        stop.set(); reader.join(timeout=1)
        absent=p3._actual_firecracker_pid(source_sock) is None

        with timer.stage("snapshot_hash_receipt","portable"):
            snap={
                "state_file":"snapshot.state",
                "memory_file":"snapshot.mem",
                "state_size_bytes":state_file.stat().st_size,
                "memory_size_bytes":mem_file.stat().st_size,
                "state_sha256":p3._sha256(state_file),
                "memory_sha256":p3._sha256(mem_file),
            }

        return {
            "schema":SCHEMA,
            "authority":"SemperSupra/agent-dispatch-private#280",
            "result":{
                "classification":"SUPPORTED" if absent else "ORACLE_FAILURE",
                "source_firecracker_pid":source_pid,
                "source_absent_before_bundle_publish":absent,
                "source_last_heartbeat_counter":last,
            },
            "snapshot":snap,
            "producer_host_fingerprint":fingerprint(),
            "portable":{
                "vmm_version":vm["version"],
                "vmm_archive_sha256":vv["actual_sha256"],
                "kernel_version":km["kernel_version"],
                "kernel_sha256":kv["actual_sha256"],
                "guest_init_binary_sha256":f1._sha256(init_bin),
                "initrd_sha256":f1._sha256(initrd),
                "machine":{"vcpu_count":config["machine-config"]["vcpu_count"],"mem_size_mib":config["machine-config"]["mem_size_mib"],"drives":0,"network_interfaces":0},
            },
            "api":{"pause":pause,"create":create,"source_termination":term},
            "lifecycle_timing":timer.receipt(),
        }


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--out-dir",type=pathlib.Path,required=True)
    a=p.parse_args()
    try: receipt=run(a.out_dir)
    except Exception as exc: receipt={"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out_dir.mkdir(parents=True,exist_ok=True)
    (a.out_dir/"producer.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1


if __name__=="__main__": raise SystemExit(main())
