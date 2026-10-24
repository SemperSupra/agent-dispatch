#!/usr/bin/env python3
"""R3a: real Agent Dispatch public contract executed inside a jailed Firecracker workcell."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
import github_runner_firecracker_j1_jailed_f3 as j1
import github_runner_firecracker_u1_userspace as u1
import github_runner_firecracker_u2_composed as u2
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-r3a-sealed-contract/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
USERSPACE_MANIFEST=pathlib.Path("experiments/firecracker/guest-userspace-ubuntu-24.04-x86_64.json")
INIT_SOURCE=pathlib.Path("experiments/firecracker/guest/r3a-bridge-init-x86_64.c")
DRIVER_SOURCE=pathlib.Path("experiments/firecracker/guest/r3a-sealed-contract-driver.py")
WORKLOAD_SOURCE=pathlib.Path("scripts/sealed_public_execution.py")
WORKLOAD_TEST=pathlib.Path("tests/test_sealed_public_execution.py")
CONTRACT_RE=re.compile(
    r"FIRECRACKER_R3A_CONTRACT exit=(\d+) tests=(\d+) ok=(\d+) elapsed_ns=(\d+) "
    r"source_sha256=([0-9a-f]{64}) test_sha256=([0-9a-f]{64})"
)
EXIT_RE=re.compile(r"FIRECRACKER_R3A_EXIT code=(\d+)")
UNITTEST_RE=re.compile(r"Ran\s+(\d+)\s+tests?\s+in\s+([0-9.]+)s")

def _sha256(path:pathlib.Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def _native_contract()->dict:
    started=time.perf_counter_ns()
    cp=subprocess.run(
        [sys.executable,"-m","unittest","-v",str(WORKLOAD_TEST)],
        capture_output=True,text=True,timeout=60,check=False,
    )
    elapsed_ns=time.perf_counter_ns()-started
    combined=(cp.stdout or "")+"\n"+(cp.stderr or "")
    m=UNITTEST_RE.search(combined)
    tests_run=int(m.group(1)) if m else None
    ok_marker=bool(re.search(r"(?:^|\n)OK(?:\n|$)",combined))
    return {
        "exit_code":cp.returncode,
        "elapsed_ns":elapsed_ns,
        "tests_run":tests_run,
        "ok_marker":ok_marker,
        "stdout_tail":(cp.stdout or "")[-4000:],
        "stderr_tail":(cp.stderr or "")[-8000:],
    }

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

def _debugfs(image:pathlib.Path,command:str,timeout:int=20)->dict:
    binary=shutil.which("debugfs")
    if not binary:
        return {"ok":False,"reason":"debugfs unavailable"}
    cp=subprocess.run([binary,"-w","-R",command,str(image)],capture_output=True,text=True,timeout=timeout,check=False)
    return {"ok":cp.returncode==0,"exit_code":cp.returncode,"stdout":cp.stdout[-2000:],"stderr":cp.stderr[-2000:]}

def _preload_scratch(image:pathlib.Path)->dict:
    commands=[
        "mkdir /r3a",
        "mkdir /r3a/scripts",
        "mkdir /r3a/tests",
        f"write {DRIVER_SOURCE.resolve()} /r3a/driver.py",
        f"write {WORKLOAD_SOURCE.resolve()} /r3a/scripts/sealed_public_execution.py",
        f"write {WORKLOAD_TEST.resolve()} /r3a/tests/test_sealed_public_execution.py",
    ]
    observations=[]
    for command in commands:
        rr=_debugfs(image,command)
        observations.append({"command":command,"result":rr})
        if not rr["ok"]:
            return {"ok":False,"observations":observations}
    return {"ok":True,"observations":observations}

def _inspect_scratch(image:pathlib.Path,work:pathlib.Path)->dict:
    debugfs=shutil.which("debugfs")
    if not debugfs:
        return {"ok":False,"reason":"debugfs unavailable"}
    outputs={
        "/r3a-result.json":work/"r3a-host-result.json",
        "/r3a/scripts/sealed_public_execution.py":work/"r3a-host-source.py",
        "/r3a/tests/test_sealed_public_execution.py":work/"r3a-host-test.py",
    }
    observations={}
    for guest,host in outputs.items():
        code,out,err=f0._run([debugfs,"-R",f"dump -p {guest} {host}",str(image)],timeout=20)
        observations[guest]={"exit_code":code,"stderr":err[-1000:] if err else ""}
        if code!=0 or not host.exists():
            return {"ok":False,"reason":f"debugfs dump failed for {guest}","observations":observations}
    try:
        result=json.loads(outputs["/r3a-result.json"].read_text())
    except Exception as exc:
        return {"ok":False,"reason":f"result JSON invalid: {exc}","observations":observations}
    return {
        "ok":True,
        "result":result,
        "source_sha256":_sha256(outputs["/r3a/scripts/sealed_public_execution.py"]),
        "test_sha256":_sha256(outputs["/r3a/tests/test_sealed_public_execution.py"]),
        "observations":observations,
    }

def _run_jailed(*,jailer,firecracker,jail_base,vm_id,uid,gid,expected_source_sha,expected_test_sha,expected_tests)->dict:
    sudo=shutil.which("sudo")
    if not sudo:
        return {"ok":False,"classification":"SETUP_REQUIRED","reason":"sudo unavailable"}
    command=[
        sudo,"-n",str(jailer),
        "--id",vm_id,
        "--exec-file",str(firecracker),
        "--uid",str(uid),"--gid",str(gid),
        "--chroot-base-dir",str(jail_base),
        "--cgroup-version","2",
        "--new-pid-ns",
        "--resource-limit","no-file=128",
        "--","--no-api","--config-file","/vm-config.json",
    ]
    host_ns={ns:os.readlink(f"/proc/self/ns/{ns}") for ns in ("mnt","pid")}
    started=time.perf_counter()
    proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    pid_file=jail_base/firecracker.name/vm_id/"root"/f"{firecracker.name}.pid"
    observation=None
    observed_pid_file=None
    deadline=time.time()+12
    while time.time()<deadline:
        obs=None
        pid_read=j1._sudo(["cat",str(pid_file)],timeout=5)
        if pid_read["ok"]:
            try:
                host_pid=int(pid_read["stdout"].strip())
                observed_pid_file={"path":str(pid_file),"host_pid":host_pid}
                obs=j1._process_observation(host_pid)
            except (ValueError,TypeError):
                obs=None
        if obs is None:
            obs=j1._find_process_by_real_uid(uid)
        if obs is not None:
            observation=obs
            if obs.get("seccomp_mode")==2:
                break
        time.sleep(0.005)
    try:
        out,err=proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill(); out,err=proc.communicate()
    elapsed_ms=round((time.perf_counter()-started)*1000.0,3)
    combined="\n".join(x for x in (out,err) if x)
    cm=CONTRACT_RE.search(combined); em=EXIT_RE.search(combined)
    observed=None
    if cm:
        observed={
            "exit_code":int(cm.group(1)),
            "tests_run":int(cm.group(2)),
            "ok_marker":cm.group(3)=="1",
            "elapsed_ns":int(cm.group(4)),
            "source_sha256":cm.group(5),
            "test_sha256":cm.group(6),
        }
    bridge_exit=int(em.group(1)) if em else None
    clean=proc.returncode==0 and "Firecracker exiting successfully" in combined
    guest_ok=bool(observed) and (
        observed["exit_code"]==0
        and observed["tests_run"]==expected_tests
        and observed["ok_marker"]
        and observed["source_sha256"]==expected_source_sha
        and observed["test_sha256"]==expected_test_sha
        and bridge_exit==0 and clean
    )
    uid_ok=bool(observation and observation.get("uid_fields") and observation["uid_fields"][0]==uid)
    gid_ok=bool(observation and observation.get("gid_fields") and observation["gid_fields"][0]==gid)
    seccomp_ok=bool(observation and observation.get("seccomp_mode")==2)
    nspid=(observation or {}).get("nspid") or []
    pidns_ok=len(nspid)>=2 and nspid[-1]==1
    mntns_ok=bool(observation and observation.get("mnt_ns") not in {None,host_ns["mnt"]})
    return {
        "ok":guest_ok and uid_ok and gid_ok and seccomp_ok and pidns_ok and mntns_ok,
        "guest_contract_oracle_satisfied":guest_ok,
        "uid_drop_observed":uid_ok,
        "gid_drop_observed":gid_ok,
        "seccomp_filter_observed":seccomp_ok,
        "new_pid_namespace_observed":pidns_ok,
        "mount_namespace_observed":mntns_ok,
        "elapsed_ms":elapsed_ms,
        "observed":observed,
        "bridge_exit_code":bridge_exit,
        "clean_vmm_exit_observed":clean,
        "process_observation":observation,
        "pid_file_observation":observed_pid_file,
        "output_tail":combined[-10000:],
    }

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}

    source_sha=_sha256(WORKLOAD_SOURCE); test_sha=_sha256(WORKLOAD_TEST)
    with timer.stage("native_contract","portable"):
        native=_native_contract()
    if native["exit_code"]!=0 or not native["ok_marker"] or native["tests_run"] is None:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"ORACLE_FAILURE","reason":"native contract baseline failed"},"native":native}

    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST); um=json.loads(USERSPACE_MANIFEST.read_text())
    identity=None; trusted_base=pathlib.Path(f"/opt/agent-dispatch-fcr3a-{os.getpid()}")
    execution=None; reconcile=None; cleanup_identity=None; root_immutable=False

    with tempfile.TemporaryDirectory(prefix="firecracker-r3a-") as td:
        w=pathlib.Path(td); archive=w/"firecracker.tgz"; extract=w/"extract"; extract.mkdir()
        kernel=w/"vmlinux"; rootfs=w/"ubuntu.squashfs"; scratch=w/"scratch.ext4"; init_bin=w/"init"; initrd=w/"initrd.cpio"; config=w/"vm.json"
        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("archive_extract","portable"):
            f0._safe_extract(archive,extract)
            firecracker=j1._find_binary(extract,f"firecracker-{vm['version']}-{vm['architecture']}")
            jailer=j1._find_binary(extract,f"jailer-{vm['version']}-{vm['architecture']}")
            firecracker.chmod(firecracker.stat().st_mode|0o111); jailer.chmod(jailer.stat().st_mode|0o111)
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
        with timer.stage("workload_capsule_stage","portable"):
            preload=_preload_scratch(scratch)
        if not preload["ok"]:
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":"scratch preload failed"},"preload":preload}
        with timer.stage("ephemeral_identity_create","venue"):
            identity=j1._create_ephemeral_identity(f"fcr3a{os.getpid()}")
        try:
            with timer.stage("trusted_runtime_stage","venue"):
                trusted=j1._stage_trusted_runtime(trusted_base,firecracker,jailer)

            cfg=f1._build_config(kernel,initrd,config)
            cfg["machine-config"]["mem_size_mib"]=512
            cfg["boot-source"]["kernel_image_path"]="/vmlinux"
            cfg["boot-source"]["initrd_path"]="/initrd.cpio"
            cfg["drives"]=[
                {"drive_id":"userspace","path_on_host":"/ubuntu.squashfs","is_root_device":False,"is_read_only":True},
                {"drive_id":"scratch","path_on_host":"/scratch.ext4","is_root_device":False,"is_read_only":False},
            ]
            cfg["network-interfaces"]=[]
            config.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")
            vm_id=f"r3a-{os.getpid()}"
            jail_root=trusted["jail_base"]/trusted["firecracker"].name/vm_id/"root"
            with timer.stage("jail_resource_stage","venue"):
                staged=u2._stage_vm_resources(
                    jail_root,kernel=kernel,initrd=initrd,rootfs=rootfs,scratch=scratch,config=config,
                    uid=identity["uid"],gid=identity["gid"],
                )
            staged_root=pathlib.Path(staged["rootfs"]); staged_scratch=pathlib.Path(staged["scratch"])
            root_before=u2._sudo_sha256(staged_root)

            with timer.stage("jailed_representative_workload","portable"):
                execution=_run_jailed(
                    jailer=trusted["jailer"],firecracker=trusted["firecracker"],jail_base=trusted["jail_base"],
                    vm_id=vm_id,uid=identity["uid"],gid=identity["gid"],
                    expected_source_sha=source_sha,expected_test_sha=test_sha,expected_tests=native["tests_run"],
                )

            exported=w/"exported-scratch.ext4"
            with timer.stage("scratch_export","venue"):
                u2._export_from_jail(staged_scratch,exported)
            with timer.stage("post_vm_reconciliation","portable"):
                reconcile=_inspect_scratch(exported,w)
            root_after=u2._sudo_sha256(staged_root)
            root_immutable=root_before==root_after==um["rootfs_sha256"]
        finally:
            with timer.stage("jail_cleanup","venue"):
                if trusted_base.exists():
                    j1._sudo(["rm","-rf",str(trusted_base)],timeout=60)
            with timer.stage("identity_cleanup","venue"):
                cleanup_identity=j1._delete_ephemeral_identity(identity) if identity else None

        guest_result=(reconcile or {}).get("result") or {}
        reconcile_ok=bool(
            reconcile and reconcile["ok"]
            and reconcile.get("source_sha256")==source_sha
            and reconcile.get("test_sha256")==test_sha
            and guest_result.get("exit_code")==0
            and guest_result.get("tests_run")==native["tests_run"]
            and guest_result.get("ok_marker") is True
            and guest_result.get("source_sha256")==source_sha
            and guest_result.get("test_sha256")==test_sha
        )
        supported=bool(execution and execution["ok"] and reconcile_ok and root_immutable)
        native_ms=native["elapsed_ns"]/1_000_000.0
        guest_work_ns=(execution.get("observed") or {}).get("elapsed_ns") if execution else None
        guest_work_ms=(guest_work_ns/1_000_000.0) if guest_work_ns is not None else None
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":"SUPPORTED" if supported else "ORACLE_FAILURE",
                "representative_contract_supported":supported,
                "exact_workload_bytes_reconciled":reconcile_ok,
                "rootfs_immutable":root_immutable,
            },
            "workload":{
                "name":"Agent Dispatch sealed-public-execution contract tests",
                "source":str(WORKLOAD_SOURCE),
                "test":str(WORKLOAD_TEST),
                "source_sha256":source_sha,
                "test_sha256":test_sha,
                "network_required":False,
                "guest_credentials":False,
            },
            "native":native,
            "jailed_firecracker":execution,
            "host_reconciliation":reconcile,
            "comparison":{
                "native_test_ms":round(native_ms,3),
                "guest_test_ms":round(guest_work_ms,3) if guest_work_ms is not None else None,
                "guest_over_native_test_ratio":round(guest_work_ms/native_ms,4) if guest_work_ms and native_ms else None,
                "full_jailed_vm_lifecycle_ms":execution.get("elapsed_ms") if execution else None,
                "lifecycle_over_native_test_ratio":round(execution["elapsed_ms"]/native_ms,4) if execution and native_ms else None,
            },
            "cleanup":{"identity":cleanup_identity},
            "lifecycle_timing":timer.receipt(),
            "next_gate":"R3b: guest-side thin harness reaching a minimum-authority inference endpoint; compare against host-side actor -> guest executor.",
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
