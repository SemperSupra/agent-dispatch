#!/usr/bin/env python3
"""W3: qualify a mandatory post-restore application reinitialization barrier."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
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
import github_runner_firecracker_w2_clone_state as w2
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-w3-post-restore-reset/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
USERSPACE_MANIFEST=pathlib.Path("experiments/firecracker/guest-userspace-ubuntu-24.04-x86_64.json")
INIT_SOURCE=pathlib.Path("experiments/firecracker/guest/w3-bridge-init-x86_64.c")
GUEST_SOURCE=pathlib.Path("experiments/firecracker/guest/w3-post-restore-reset.py")
READY_RE=re.compile(r"FIRECRACKER_W3_TEMPLATE_READY template=([0-9a-f]{32}) python=(\S+) pid=(\d+)")
RESET_RE=re.compile(
    r"FIRECRACKER_W3_RESET template=([0-9a-f]{32}) seed_sha256=([0-9a-f]{64}) "
    r"session=([0-9a-f]{32}) py_random=([0-9a-f]{32}) secrets=([0-9a-f]{32}) "
    r"work_digest=([0-9a-f]{64})"
)
EXIT_RE=re.compile(r"FIRECRACKER_W3_EXIT code=(\d+)")
VMFORK_MARKER="crng reseeded due to virtual machine fork"

def _preload_payload(image:pathlib.Path)->dict:
    import shutil, subprocess
    debugfs=shutil.which("debugfs")
    if not debugfs:
        return {"ok":False,"reason":"debugfs unavailable"}
    cp=subprocess.run(
        [debugfs,"-w","-R",f"write {GUEST_SOURCE.resolve()} /w3.py",str(image)],
        capture_output=True,text=True,timeout=20,check=False,
    )
    return {"ok":cp.returncode==0,"stdout":cp.stdout[-2000:],"stderr":cp.stderr[-2000:]}

def _expected_work_digest(session:str,py_random:str)->str:
    return hashlib.sha256(("work:"+session+":"+py_random).encode()).hexdigest()

def _restore_clone(*,index:int,firecracker:pathlib.Path,snapshot:pathlib.Path,memory:pathlib.Path,work:pathlib.Path)->dict:
    sock=work/f"clone{index}.sock"
    lines=[]; stop=threading.Event()
    proc=p3._launch(firecracker,sock,None)
    reader=threading.Thread(target=p3._reader,args=(proc,lines,stop),daemon=True)
    reader.start()
    if not p3._wait_for_socket(sock,5):
        p3._terminate_group(proc)
        return {"ok":False,"reason":"API socket not ready"}

    pid=p3._actual_firecracker_pid(sock)
    load_started=time.perf_counter()
    load=p3._api(sock,"PUT","/snapshot/load",{
        "snapshot_path":str(snapshot.resolve()),
        "mem_backend":{"backend_path":str(memory.resolve()),"backend_type":"File"},
        "track_dirty_pages":False,
        "resume_vm":False,
    })
    if not load["ok"]:
        p3._terminate_group(proc)
        return {"ok":False,"reason":"snapshot load failed","load":load}

    resume_started=time.perf_counter()
    resume=p3._api(sock,"PATCH","/vm",{"state":"Resumed"})
    if not resume["ok"]:
        p3._terminate_group(proc)
        return {"ok":False,"reason":"resume failed","resume":resume}

    marker=p3._wait_for_regex(lines,RESET_RE,5)
    resume_to_marker_ms=round((time.perf_counter()-resume_started)*1000.0,3) if marker else None
    load_to_marker_ms=round((time.perf_counter()-load_started)*1000.0,3) if marker else None
    try:
        rc=proc.wait(timeout=5)
    except __import__("subprocess").TimeoutExpired:
        rc=p3._terminate_group(proc)["return_code"]
    stop.set(); reader.join(timeout=1)

    ready_seen=any(READY_RE.search(line) for line in lines)
    exit_values=[int(m.group(1)) for line in lines if (m:=EXIT_RE.search(line))]
    observed=None
    if marker:
        observed={
            "template":marker.group(1),
            "seed_sha256":marker.group(2),
            "session":marker.group(3),
            "py_random":marker.group(4),
            "secrets":marker.group(5),
            "work_digest":marker.group(6),
        }
    work_ok=bool(observed) and observed["work_digest"]==_expected_work_digest(observed["session"],observed["py_random"])
    reseed=any(VMFORK_MARKER in line for line in lines)
    return {
        "ok":bool(observed) and work_ok and not ready_seen and bool(exit_values) and max(exit_values)==0 and rc==0,
        "index":index,
        "firecracker_pid":pid,
        "destination_reemitted_template_ready":ready_seen,
        "exit_code":rc,
        "observed":observed,
        "work_digest_valid":work_ok,
        "vmfork_crng_reseed_log_observed":reseed,
        "snapshot_load_ms":load.get("elapsed_ms"),
        "resume_api_ms":resume.get("elapsed_ms"),
        "resume_to_reset_marker_ms":resume_to_marker_ms,
        "load_start_to_reset_marker_ms":load_to_marker_ms,
        "output_tail":"\n".join(lines[-100:]),
    }

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    vm=f1._load_json(f3.VMM_MANIFEST)
    km=f1._load_json(f3.KERNEL_MANIFEST)
    um=json.loads(USERSPACE_MANIFEST.read_text())

    with tempfile.TemporaryDirectory(prefix="firecracker-w3-") as td:
        work=pathlib.Path(td)
        archive=work/"firecracker.tgz"; extract=work/"extract"; extract.mkdir()
        kernel=work/"vmlinux"; rootfs=work/"ubuntu.squashfs"; payload=work/"payload.ext4"
        init_bin=work/"init"; initrd=work/"initrd.cpio"; config_path=work/"source-config.json"
        source_sock=work/"source.sock"; state_file=work/"snapshot.state"; mem_file=work/"snapshot.mem"

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
            w2._build_initramfs(init_bin,initrd)
        with timer.stage("payload_ext4_create","venue"):
            ps=u1._make_scratch(payload)
        if not ps["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":ps["reason"]}}
        with timer.stage("payload_preload","portable"):
            preload=_preload_payload(payload)
        if not preload["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":"payload preload failed","preload":preload}}

        root_before=u1._sha256(rootfs); payload_before=u1._sha256(payload)
        cfg=f1._build_config(kernel,initrd,config_path)
        cfg["machine-config"]["vcpu_count"]=1
        cfg["machine-config"]["mem_size_mib"]=512
        cfg["drives"]=[
            {"drive_id":"userspace","path_on_host":str(rootfs.resolve()),"is_root_device":False,"is_read_only":True},
            {"drive_id":"payload","path_on_host":str(payload.resolve()),"is_root_device":False,"is_read_only":True},
        ]
        cfg["network-interfaces"]=[]
        config_path.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

        source_lines=[]; source_stop=threading.Event()
        source=p3._launch(firecracker,source_sock,config_path)
        source_reader=threading.Thread(target=p3._reader,args=(source,source_lines,source_stop),daemon=True)
        source_reader.start()
        if not p3._wait_for_socket(source_sock,5):
            p3._terminate_group(source)
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":"source API socket not ready"}}
        ready=p3._wait_for_regex(source_lines,READY_RE,8)
        if not ready:
            p3._terminate_group(source)
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"template READY not observed"}}
        template_nonce=ready.group(1)
        source_pid=p3._actual_firecracker_pid(source_sock)

        with timer.stage("pause_api","portable"):
            pause=p3._api(source_sock,"PATCH","/vm",{"state":"Paused"})
        if not pause["ok"]:
            p3._terminate_group(source)
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"pause failed","pause":pause}}
        time.sleep(0.03)
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
        source_absent=p3._actual_firecracker_pid(source_sock) is None

        with timer.stage("clone1_restore_and_reset","portable"):
            clone1=_restore_clone(index=1,firecracker=firecracker,snapshot=state_file,memory=mem_file,work=work)
        clone1_absent=True
        if clone1.get("firecracker_pid"):
            clone1_absent=not pathlib.Path(f"/proc/{clone1['firecracker_pid']}").exists()

        with timer.stage("clone2_restore_and_reset","portable"):
            clone2=_restore_clone(index=2,firecracker=firecracker,snapshot=state_file,memory=mem_file,work=work)

        root_after=u1._sha256(rootfs); payload_after=u1._sha256(payload)
        images_unchanged=(root_before==root_after==um["rootfs_sha256"] and payload_before==payload_after)

        o1=clone1.get("observed") or {}; o2=clone2.get("observed") or {}
        template_matches=(
            o1.get("template")==template_nonce
            and o2.get("template")==template_nonce
        )
        reset_unique={
            "seed_material_unique":o1.get("seed_sha256")!=o2.get("seed_sha256"),
            "session_unique":o1.get("session")!=o2.get("session"),
            "python_prng_unique":o1.get("py_random")!=o2.get("py_random"),
            "secrets_unique":o1.get("secrets")!=o2.get("secrets"),
        }
        all_reset_unique=all(reset_unique.values())
        distinct_pids=(
            source_pid is not None
            and clone1.get("firecracker_pid") is not None
            and clone2.get("firecracker_pid") is not None
            and len({source_pid,clone1["firecracker_pid"],clone2["firecracker_pid"]})==3
        )
        reseed_logs=bool(clone1.get("vmfork_crng_reseed_log_observed") and clone2.get("vmfork_crng_reseed_log_observed"))

        with timer.stage("snapshot_hash_receipt","portable"):
            snapshot={
                "state_size_bytes":state_file.stat().st_size,
                "mem_size_bytes":mem_file.stat().st_size,
                "state_sha256":u1._sha256(state_file),
                "mem_sha256":u1._sha256(mem_file),
            }

        supported=bool(
            clone1.get("ok") and clone2.get("ok")
            and source_absent and clone1_absent
            and template_matches and all_reset_unique
            and distinct_pids and images_unchanged and reseed_logs
        )
        return {
            "schema":SCHEMA,
            "authority":AUTHORITY,
            "requested_label":label,
            "result":{
                "classification":"SUPPORTED" if supported else "ORACLE_FAILURE",
                "post_restore_reinitialization_supported":supported,
                "source_absent_before_clones":source_absent,
                "clone1_absent_before_clone2":clone1_absent,
                "template_nonce_matches_both_clones":template_matches,
                "distinct_firecracker_pids":distinct_pids,
                "read_only_images_unchanged":images_unchanged,
                "vmfork_reseed_observed_both":reseed_logs,
            },
            "template":{"nonce":template_nonce,"source_firecracker_pid":source_pid},
            "clone1":clone1,
            "clone2":clone2,
            "reinitialization":reset_unique,
            "snapshot":snapshot,
            "api":{"pause":pause,"create":create,"source_termination":source_term},
            "lifecycle_timing":timer.receipt(),
            "qualified_template_rule":"Snapshot only at TEMPLATE_READY barrier; source never resumes; every clone must reinitialize application identity/PRNG/capability state before accepting work.",
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
