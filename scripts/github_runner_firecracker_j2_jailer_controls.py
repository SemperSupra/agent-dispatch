#!/usr/bin/env python3
"""J2: qualify selected Firecracker jailer isolation/resource controls one at a time."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
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
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-j2-jailer-controls/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
MANIFEST=pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")
KERNEL_MANIFEST=pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")


def _sudo_text(argv:list[str], timeout:int=10)->dict:
    return j1._sudo(argv,timeout=timeout)


def _limits(pid:int)->dict:
    result=_sudo_text(["cat",f"/proc/{pid}/limits"],timeout=5)
    parsed={}
    if result["ok"]:
        for line in result["stdout"].splitlines():
            if line.startswith("Max open files"):
                parts=line.split()
                parsed["no_file_soft"]=parts[3]
                parsed["no_file_hard"]=parts[4]
            elif line.startswith("Max file size"):
                parts=line.split()
                parsed["fsize_soft"]=parts[3]
                parsed["fsize_hard"]=parts[4]
    return {"ok":result["ok"],"parsed":parsed,"raw_tail":result["stdout"][-3000:]}


def _cgroup_state(pid:int)->dict:
    cg=_sudo_text(["cat",f"/proc/{pid}/cgroup"],timeout=5)
    if not cg["ok"]:
        return {"ok":False,"error":cg["stderr"]}
    rel=None
    for line in cg["stdout"].splitlines():
        parts=line.split(":",2)
        if len(parts)==3 and parts[0]=="0":
            rel=parts[2]
            break
    result={"ok":True,"relative_path":rel}
    if rel:
        root=pathlib.Path("/sys/fs/cgroup")/rel.lstrip("/")
        result["path"]=str(root)
        for name in ("memory.max","pids.max","cpu.max"):
            p=root/name
            try:
                result[name.replace(".","_")]=p.read_text().strip()
            except OSError:
                result[name.replace(".","_")]=None
    return result


def _observe_uid(uid:int)->dict|None:
    candidate=j1._find_process_by_real_uid(uid)
    if candidate is None:
        return None
    pid=candidate["pid"]
    candidate["limits"]=_limits(pid)
    candidate["cgroup"]=_cgroup_state(pid)
    return candidate


def _run_variant(
    *,
    name:str,
    jailer:pathlib.Path,
    firecracker:pathlib.Path,
    jail_base:pathlib.Path,
    vm_id:str,
    uid:int,
    gid:int,
    expected:dict,
    extra_args:list[str],
)->dict:
    sudo=shutil.which("sudo")
    if not sudo:
        return {"name":name,"classification":"SETUP_REQUIRED","reason":"sudo unavailable"}

    command=[
        sudo,"-n",str(jailer),
        "--id",vm_id,
        "--exec-file",str(firecracker),
        "--uid",str(uid),
        "--gid",str(gid),
        "--chroot-base-dir",str(jail_base),
        "--cgroup-version","2",
        *extra_args,
        "--",
        "--no-api",
        "--config-file","/vm-config.json",
    ]
    host_ns={
        ns: os.readlink(f"/proc/self/ns/{ns}")
        for ns in ("mnt","pid","net","user")
    }
    started=time.perf_counter()
    proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    pid_file=jail_base/firecracker.name/vm_id/"root"/f"{firecracker.name}.pid"
    latest=None
    deadline=time.time()+10
    while time.time()<deadline and proc.poll() is None:
        obs=None
        if pid_file.exists():
            try:
                obs=j1._process_observation(int(pid_file.read_text().strip()))
                if obs.get("pid"):
                    obs["limits"]=_limits(obs["pid"])
                    obs["cgroup"]=_cgroup_state(obs["pid"])
            except (OSError,ValueError):
                obs=None
        if obs is None:
            obs=_observe_uid(uid)
        if obs is not None:
            latest=obs
            if obs.get("seccomp_mode")==2:
                time.sleep(0.02)
                if pid_file.exists():
                    try:
                        obs2=j1._process_observation(int(pid_file.read_text().strip()))
                        if obs2.get("pid"):
                            obs2["limits"]=_limits(obs2["pid"])
                            obs2["cgroup"]=_cgroup_state(obs2["pid"])
                        latest=obs2
                    except (OSError,ValueError):
                        pass
                break
        time.sleep(0.005)
    try:
        out,err=proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill(); out,err=proc.communicate()
    elapsed=round((time.perf_counter()-started)*1000.0,3)
    combined="\n".join(x for x in (out,err) if x)

    rm=f3.RESULT_RE.search(combined)
    em=f3.EXIT_RE.search(combined)
    candidate=None
    if rm:
        candidate={
            "bytes":int(rm.group(1)),"lines":int(rm.group(2)),"words":int(rm.group(3)),
            "fnv1a64":rm.group(4),"work_ns":int(rm.group(5)),
        }
    child=None
    if em:
        child={"exit_code":int(em.group(1)),"elapsed_ns":int(em.group(2))}
    expected_match=bool(candidate) and all(candidate[k]==expected[k] for k in ("bytes","lines","words","fnv1a64"))
    guest_ok=expected_match and bool(child) and child["exit_code"]==0 and proc.returncode==0 and "Firecracker exiting successfully" in combined

    evidence={"process":latest,"host_namespaces":host_ns}
    control_ok=False
    reason=None
    if name=="new_pid_ns":
        control_ok=bool(latest) and latest.get("pid_ns") not in {None,host_ns["pid"]}
        reason="PID namespace differs from host" if control_ok else "PID namespace difference not observed"
    elif name=="no_file_128":
        parsed=((latest or {}).get("limits") or {}).get("parsed") or {}
        control_ok=parsed.get("no_file_soft")=="128" and parsed.get("no_file_hard")=="128"
        reason="RLIMIT_NOFILE=128 observed" if control_ok else "requested RLIMIT_NOFILE not observed"
    elif name=="fsize_1m":
        parsed=((latest or {}).get("limits") or {}).get("parsed") or {}
        control_ok=parsed.get("fsize_soft")=="1048576" and parsed.get("fsize_hard")=="1048576"
        reason="RLIMIT_FSIZE=1MiB observed" if control_ok else "requested RLIMIT_FSIZE not observed"
    elif name=="cgroup_memory_512m":
        cg=(latest or {}).get("cgroup") or {}
        control_ok=cg.get("memory_max")=="536870912"
        reason="cgroup-v2 memory.max=512MiB observed" if control_ok else "requested cgroup memory.max not observed"

    if guest_ok and control_ok:
        classification="SUPPORTED"
    elif guest_ok and name=="cgroup_memory_512m" and latest is not None:
        classification="VENUE_LIMITATION"
    else:
        classification="ORACLE_FAILURE"

    return {
        "name":name,
        "classification":classification,
        "guest_oracle_satisfied":guest_ok,
        "control_oracle_satisfied":control_ok,
        "control_reason":reason,
        "elapsed_ms":elapsed,
        "return_code":proc.returncode,
        "candidate_result":candidate,
        "candidate_exit":child,
        "evidence":evidence,
        "output_tail":combined[-7000:],
    }


def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    vm=json.loads(MANIFEST.read_text())
    km=json.loads(KERNEL_MANIFEST.read_text())
    data=f3.DEFAULT_INPUT.read_bytes()
    expected=f3.expected_result(data)
    identity=None
    trusted_base=pathlib.Path(f"/opt/agent-dispatch-fcj2-{os.getpid()}")

    with tempfile.TemporaryDirectory(prefix="firecracker-j2-") as td:
        w=pathlib.Path(td)
        archive=w/"firecracker.tgz"; extract=w/"extract"; extract.mkdir()
        kernel=w/"vmlinux"; init_bin=w/"init"; cand_bin=w/"candidate"; initrd=w/"initrd.cpio"
        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("archive_extract","portable"):
            f0._safe_extract(archive,extract)
            firecracker=j1._find_binary(extract,f"firecracker-{vm['version']}-{vm['architecture']}")
            jailer=j1._find_binary(extract,f"jailer-{vm['version']}-{vm['architecture']}")
            firecracker.chmod(firecracker.stat().st_mode|0o111); jailer.chmod(jailer.stat().st_mode|0o111)
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

        with timer.stage("ephemeral_identity_create","venue"):
            identity=j1._create_ephemeral_identity(f"fcj2{os.getpid()}")
        try:
            with timer.stage("trusted_runtime_stage","venue"):
                trusted=j1._stage_trusted_runtime(trusted_base,firecracker,jailer)
            variants=[
                ("new_pid_ns",["--new-pid-ns"]),
                ("no_file_128",["--resource-limit","no-file=128"]),
                ("fsize_1m",["--resource-limit","fsize=1048576"]),
                ("cgroup_memory_512m",["--cgroup","memory.max=536870912","--parent-cgroup","agent-dispatch-fcj2"]),
            ]
            results=[]
            for index,(name,args) in enumerate(variants):
                vm_id=f"j2-{index}-{os.getpid()}"
                jail_root=trusted["jail_base"]/trusted["firecracker"].name/vm_id/"root"
                config={
                    "boot-source":{"kernel_image_path":"/vmlinux","initrd_path":"/initrd.cpio","boot_args":"console=ttyS0 reboot=k panic=1 pci=off"},
                    "drives":[],
                    "machine-config":{"vcpu_count":1,"mem_size_mib":128,"smt":False,"track_dirty_pages":False,"huge_pages":"None"},
                    "network-interfaces":[],
                }
                with timer.stage(f"stage_{name}","venue"):
                    j1._stage_jail_files(jail_root,kernel,initrd,config,identity["uid"],identity["gid"])
                with timer.stage(f"run_{name}","portable"):
                    result=_run_variant(
                        name=name,jailer=trusted["jailer"],firecracker=trusted["firecracker"],
                        jail_base=trusted["jail_base"],vm_id=vm_id,uid=identity["uid"],gid=identity["gid"],
                        expected=expected,extra_args=args,
                    )
                results.append(result)
                # Best-effort cleanup of any cgroup the jailer created.
                if name=="cgroup_memory_512m":
                    j1._sudo(["rmdir",f"/sys/fs/cgroup/agent-dispatch-fcj2/{vm_id}"])
                    j1._sudo(["rmdir","/sys/fs/cgroup/agent-dispatch-fcj2"])
        finally:
            with timer.stage("jail_cleanup","venue"):
                if trusted_base.exists():
                    j1._sudo(["rm","-rf",str(trusted_base)])
            with timer.stage("identity_cleanup","venue"):
                cleanup=j1._delete_ephemeral_identity(identity) if identity else None

        supported=[r for r in results if r["classification"]=="SUPPORTED"]
        limitations=[r for r in results if r["classification"]=="VENUE_LIMITATION"]
        failures=[r for r in results if r["classification"]=="ORACLE_FAILURE"]
        classification="SUPPORTED" if len(supported)==len(results) else "PARTIAL" if not failures else "ORACLE_FAILURE"
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":classification,
                "supported_controls":[r["name"] for r in supported],
                "venue_limited_controls":[r["name"] for r in limitations],
                "failed_controls":[r["name"] for r in failures],
            },
            "identity":identity,"identity_cleanup":cleanup,
            "variants":results,
            "lifecycle_timing":timer.receipt(),
            "next_gate":"J3 jailed concurrency and R0 resource envelope",
        }


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try: receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n"); print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED","PARTIAL"} else 1

if __name__=="__main__": raise SystemExit(main())
