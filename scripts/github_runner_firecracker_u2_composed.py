#!/usr/bin/env python3
"""U2: compose jailer + normal Ubuntu userspace + writable scratch + bounded HTTPS egress."""
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
import github_runner_firecracker_r2_network as r2
import github_runner_firecracker_u1_userspace as u1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA="firecracker-u2-jailed-connected-userspace/v1"
AUTHORITY="SemperSupra/agent-dispatch-private#287"
USERSPACE_MANIFEST=pathlib.Path("experiments/firecracker/guest-userspace-ubuntu-24.04-x86_64.json")
INIT_SOURCE=pathlib.Path("experiments/firecracker/guest/u2-bridge-init-x86_64.c")
PROBE_SOURCE=pathlib.Path("experiments/firecracker/guest/u2-composed-probe.py")
PAYLOAD=b"firecracker-u2-jailed-network-userspace\n"
PAYLOAD_SHA256=hashlib.sha256(PAYLOAD).hexdigest()
U2_RE=re.compile(
    r"FIRECRACKER_U2_COMPOSED os_id=(\S+) os_version=(\S+) python=(\S+) arch=(\S+) "
    r"shell=(\d+) tools=(\S+) https_status=(\d+) body_bytes=(\d+) tls=(\S+) "
    r"metadata_blocked=(\d+) host_blocked=(\d+) scratch_sha256=([0-9a-f]{64})"
)
EXIT_RE=re.compile(r"FIRECRACKER_U2_EXIT code=(\d+)")

def _sha256(path:pathlib.Path)->str:
    return u1._sha256(path)

def _build_initramfs(init_bin:pathlib.Path,probe:pathlib.Path,out:pathlib.Path)->None:
    import stat
    resolv=b"nameserver 1.1.1.1\noptions timeout:1 attempts:2\n"
    payload=b"".join([
        f1._newc_entry(".",mode=stat.S_IFDIR|0o755,ino=1,nlink=2),
        f1._newc_entry("dev",mode=stat.S_IFDIR|0o755,ino=2,nlink=2),
        f1._newc_entry("dev/console",mode=stat.S_IFCHR|0o600,ino=3,rdevmajor=5,rdevminor=1),
        f1._newc_entry("dev/vda",mode=stat.S_IFBLK|0o660,ino=4,rdevmajor=254,rdevminor=0),
        f1._newc_entry("dev/vdb",mode=stat.S_IFBLK|0o660,ino=5,rdevmajor=254,rdevminor=16),
        f1._newc_entry("newroot",mode=stat.S_IFDIR|0o755,ino=6,nlink=2),
        f1._newc_entry("work",mode=stat.S_IFDIR|0o755,ino=7,nlink=2),
        f1._newc_entry("work/u2.py",mode=stat.S_IFREG|0o444,data=probe.read_bytes(),ino=8),
        f1._newc_entry("work/resolv.conf",mode=stat.S_IFREG|0o444,data=resolv,ino=9),
        f1._newc_entry("init",mode=stat.S_IFREG|0o755,data=init_bin.read_bytes(),ino=10),
        f1._newc_entry("TRAILER!!!",mode=0,ino=11),
    ])
    out.write_bytes(payload)

def _stage_file(src:pathlib.Path,dst:pathlib.Path,uid:int,gid:int,mode:str,sparse:bool=False)->None:
    cp=["cp"]
    if sparse: cp.append("--sparse=always")
    cp += [str(src),str(dst)]
    for argv in [
        ["mkdir","-p",str(dst.parent)],
        cp,
        ["chown",f"{uid}:{gid}",str(dst)],
        ["chmod",mode,str(dst)],
    ]:
        rr=j1._sudo(argv,timeout=60)
        if not rr["ok"]:
            raise RuntimeError(f"stage failed {argv}: {rr['stderr']}")

def _stage_vm_resources(jail_root:pathlib.Path,*,kernel,initrd,rootfs,scratch,config,uid,gid)->dict:
    mapping={
        "kernel":(kernel,jail_root/"vmlinux","0444",False),
        "initrd":(initrd,jail_root/"initrd.cpio","0444",False),
        "rootfs":(rootfs,jail_root/"ubuntu.squashfs","0444",True),
        "scratch":(scratch,jail_root/"scratch.ext4","0660",True),
        "config":(config,jail_root/"vm-config.json","0444",False),
    }
    for src,dst,mode,sparse in mapping.values():
        _stage_file(src,dst,uid,gid,mode,sparse)
    return {name:str(spec[1]) for name,spec in mapping.items()}

def _parse_output(combined:str)->tuple[dict|None,int|None]:
    m=U2_RE.search(combined); em=EXIT_RE.search(combined)
    observed=None
    if m:
        tools={}
        for item in m.group(6).split(","):
            name,value=item.split(":",1); tools[name]=value=="1"
        observed={
            "os_id":m.group(1),"os_version":m.group(2),"python_version":m.group(3),
            "architecture":m.group(4),"shell_ok":m.group(5)=="1","tools":tools,
            "https_status":int(m.group(7)),"body_bytes":int(m.group(8)),"tls_version":m.group(9),
            "metadata_blocked":m.group(10)=="1","host_blocked":m.group(11)=="1",
            "scratch_sha256":m.group(12),
        }
    return observed,int(em.group(1)) if em else None

def _inspect_scratch(image:pathlib.Path,work:pathlib.Path)->dict:
    debugfs=shutil.which("debugfs")
    if not debugfs: return {"ok":False,"reason":"debugfs unavailable"}
    result_file=work/"u2-host-result.json"; payload_file=work/"u2-host-payload.bin"
    for guest,host in [("/u2-result.json",result_file),("/u2-payload.bin",payload_file)]:
        code,out,err=f0._run([debugfs,"-R",f"dump -p {guest} {host}",str(image)],timeout=20)
        if code!=0 or not host.exists():
            return {"ok":False,"reason":f"debugfs dump failed for {guest}","stderr":err[-1000:] if err else ""}
    try: result=json.loads(result_file.read_text())
    except Exception as exc: return {"ok":False,"reason":f"result JSON invalid: {exc}"}
    payload_sha=_sha256(payload_file)
    ok=(
        result.get("os_id")=="ubuntu" and result.get("os_version")=="24.04"
        and result.get("architecture")=="x86_64" and result.get("shell_ok") is True
        and all((result.get("tools") or {}).get(t) is True for t in ("curl","fio","ip","strace"))
        and 200<=int(result.get("https_status",0))<400 and int(result.get("https_body_bytes",0))>0
        and result.get("tls_version") in ("TLSv1.2","TLSv1.3")
        and result.get("metadata_blocked") is True and result.get("host_blocked") is True
        and result.get("payload_sha256")==PAYLOAD_SHA256 and payload_sha==PAYLOAD_SHA256
        and payload_file.stat().st_size==len(PAYLOAD)
    )
    return {"ok":ok,"result":result,"payload_sha256":payload_sha,"payload_size_bytes":payload_file.stat().st_size}

def _run_jailed(*,jailer,firecracker,jail_base,vm_id,uid,gid)->dict:
    sudo=shutil.which("sudo")
    if not sudo: return {"ok":False,"classification":"SETUP_REQUIRED","reason":"sudo unavailable"}
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
    observation=None
    deadline=time.time()+12
    while time.time()<deadline and proc.poll() is None:
        obs=j1._find_process_by_real_uid(uid)
        if obs is not None:
            observation=obs
            if obs.get("seccomp_mode")==2: break
        time.sleep(0.005)
    try: out,err=proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill(); out,err=proc.communicate()
    elapsed=round((time.perf_counter()-started)*1000.0,3)
    combined="\n".join(x for x in (out,err) if x)
    observed,exit_code=_parse_output(combined)
    clean=proc.returncode==0 and "Firecracker exiting successfully" in combined
    guest_ok=bool(observed) and (
        observed["os_id"]=="ubuntu" and observed["os_version"]=="24.04"
        and observed["architecture"]=="x86_64" and observed["shell_ok"]
        and all(observed["tools"].get(t,False) for t in ("curl","fio","ip","strace"))
        and 200<=observed["https_status"]<400 and observed["body_bytes"]>0
        and observed["tls_version"] in ("TLSv1.2","TLSv1.3")
        and observed["metadata_blocked"] and observed["host_blocked"]
        and observed["scratch_sha256"]==PAYLOAD_SHA256
        and exit_code==0 and clean
    )
    uid_ok=bool(observation and observation.get("uid_fields") and observation["uid_fields"][0]==uid)
    gid_ok=bool(observation and observation.get("gid_fields") and observation["gid_fields"][0]==gid)
    seccomp_ok=bool(observation and observation.get("seccomp_mode")==2)
    pidns_ok=bool(observation and observation.get("pid_ns") not in {None,host_ns["pid"]})
    mntns_ok=bool(observation and observation.get("mnt_ns") not in {None,host_ns["mnt"]})
    return {
        "ok":guest_ok and uid_ok and gid_ok and seccomp_ok and pidns_ok and mntns_ok,
        "guest_oracle_satisfied":guest_ok,
        "uid_drop_observed":uid_ok,"gid_drop_observed":gid_ok,"seccomp_filter_observed":seccomp_ok,
        "new_pid_namespace_observed":pidns_ok,"mount_namespace_observed":mntns_ok,
        "elapsed_ms":elapsed,"return_code":proc.returncode,"u2_exit_code":exit_code,
        "observed":observed,"process_observation":observation,"clean_vmm_exit_observed":clean,
        "output_tail":combined[-12000:],
    }

def run_probe(label:str)->dict:
    timer=LifecycleTimer()
    if platform.system()!="Linux" or platform.machine() not in {"x86_64","amd64"}:
        return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED"}}
    vm=f1._load_json(f3.VMM_MANIFEST); km=f1._load_json(f3.KERNEL_MANIFEST); um=json.loads(USERSPACE_MANIFEST.read_text())
    identity=None; trusted_base=pathlib.Path(f"/opt/agent-dispatch-fcu2-{os.getpid()}"); network=None
    execution=None; ruleset=""; scratch_result=None; root_immutable=False; cleanup_network=None; cleanup_identity=None

    with tempfile.TemporaryDirectory(prefix="firecracker-u2-") as td:
        w=pathlib.Path(td);archive=w/"firecracker.tgz";extract=w/"extract";extract.mkdir()
        kernel=w/"vmlinux";rootfs=w/"ubuntu.squashfs";scratch=w/"scratch.ext4";init_bin=w/"init";initrd=w/"initrd.cpio";config=w/"vm.json"
        with timer.stage("vmm_download_and_verify","venue"): vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
        with timer.stage("archive_extract","portable"):
            f0._safe_extract(archive,extract)
            firecracker=j1._find_binary(extract,f"firecracker-{vm['version']}-{vm['architecture']}")
            jailer=j1._find_binary(extract,f"jailer-{vm['version']}-{vm['architecture']}")
            firecracker.chmod(firecracker.stat().st_mode|0o111); jailer.chmod(jailer.stat().st_mode|0o111)
        with timer.stage("kernel_download_and_verify","venue"): kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
        with timer.stage("userspace_download_and_verify","venue"): uv=f1._download_and_verify(um["rootfs_url"],um["rootfs_sha256"],rootfs)
        with timer.stage("bridge_init_compile","portable"): ic=f1._compile_init(INIT_SOURCE,init_bin)
        if not all([vv["verified"],kv["verified"],uv["verified"],ic["ok"]]):
            return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("initramfs_build","portable"): _build_initramfs(init_bin,PROBE_SOURCE,initrd)
        with timer.stage("scratch_ext4_create","venue"): ss=u1._make_scratch(scratch)
        if not ss["ok"]: return {"schema":SCHEMA,"authority":AUTHORITY,"result":{"classification":"SETUP_REQUIRED","reason":ss["reason"]}}
        with timer.stage("ephemeral_identity_create","venue"): identity=j1._create_ephemeral_identity(f"fcu2{os.getpid()}")
        try:
            with timer.stage("trusted_runtime_stage","venue"): trusted=j1._stage_trusted_runtime(trusted_base,firecracker,jailer)
            with timer.stage("host_network_setup","venue"): network=r2._setup_network(w,tap_owner_uid=identity["uid"])

            cfg=f1._build_config(kernel,initrd,config)
            cfg["machine-config"]["mem_size_mib"]=512
            cfg["boot-source"]["boot_args"] += f" ip={r2.GUEST_IP}::{r2.TAP_IP}:255.255.255.252::eth0:off"
            cfg["drives"]=[
                {"drive_id":"userspace","path_on_host":"/ubuntu.squashfs","is_root_device":False,"is_read_only":True},
                {"drive_id":"scratch","path_on_host":"/scratch.ext4","is_root_device":False,"is_read_only":False},
            ]
            cfg["network-interfaces"]=[{"iface_id":"u2net0","guest_mac":"06:00:00:00:02:12","host_dev_name":network["tap"]}]
            config.write_text(json.dumps(cfg,indent=2,sort_keys=True)+"\n")

            vm_id=f"u2-{os.getpid()}"
            jail_root=trusted["jail_base"]/trusted["firecracker"].name/vm_id/"root"
            with timer.stage("jail_resource_stage","venue"):
                staged=_stage_vm_resources(
                    jail_root,kernel=kernel,initrd=initrd,rootfs=rootfs,scratch=scratch,config=config,
                    uid=identity["uid"],gid=identity["gid"],
                )
            staged_root=pathlib.Path(staged["rootfs"]); staged_scratch=pathlib.Path(staged["scratch"])
            root_before=_sha256(staged_root)

            with timer.stage("jailed_connected_userspace_lifecycle","portable"):
                execution=_run_jailed(
                    jailer=trusted["jailer"],firecracker=trusted["firecracker"],jail_base=trusted["jail_base"],
                    vm_id=vm_id,uid=identity["uid"],gid=identity["gid"],
                )
            ruleset=r2._network_ruleset(network)
            metadata_counter=r2._counter_for(ruleset,"169.254.0.0/16")
            nat_counter=r2._counter_for(ruleset,"MASQUERADE")
            with timer.stage("post_vm_scratch_reconciliation","portable"): scratch_result=_inspect_scratch(staged_scratch,w)
            root_after=_sha256(staged_root)
            root_immutable=root_before==root_after==um["rootfs_sha256"]
        finally:
            with timer.stage("host_network_cleanup","venue"): cleanup_network=r2._cleanup_network(network)
            with timer.stage("jail_cleanup","venue"):
                if trusted_base.exists(): j1._sudo(["rm","-rf",str(trusted_base)],timeout=60)
            with timer.stage("identity_cleanup","venue"):
                cleanup_identity=j1._delete_ephemeral_identity(identity) if identity else None

        policy_ok=(metadata_counter>=1 and nat_counter>=1 and cleanup_network and cleanup_network["ok"])
        supported=bool(execution and execution["ok"] and scratch_result and scratch_result["ok"] and root_immutable and policy_ok)
        return {
            "schema":SCHEMA,"authority":AUTHORITY,"requested_label":label,
            "result":{
                "classification":"SUPPORTED" if supported else "ORACLE_FAILURE",
                "jailed_connected_userspace_supported":supported,
                "jailer_oracles_satisfied":bool(execution and execution["ok"]),
                "scratch_reconciled":bool(scratch_result and scratch_result["ok"]),
                "rootfs_immutable":root_immutable,
                "network_policy_satisfied":policy_ok,
            },
            "execution":execution,
            "host_reconciliation":scratch_result,
            "network_policy":{"metadata_drop_packets":metadata_counter,"nat_packets":nat_counter,"ruleset":ruleset[-8000:]},
            "cleanup":{"network":cleanup_network,"identity":cleanup_identity},
            "lifecycle_timing":timer.receipt(),
            "next_gate":"R3: compare host-side actor -> guest executor against guest-side thin harness -> minimum-authority inference endpoint; no broad provider key injection.",
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
