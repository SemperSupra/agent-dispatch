#!/usr/bin/env python3
"""P5 helper for a long-lived, networkless Firecracker witness microVM."""
from __future__ import annotations
import argparse,json,os,pathlib,re,shutil,subprocess,sys,time

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_p3_same_host_handoff as p3
from firecracker_host_fingerprint import fingerprint
from firecracker_lifecycle_timing import LifecycleTimer

INIT_SOURCE=pathlib.Path("experiments/firecracker/p5/rendezvous-init-x86_64.c")
READY_RE=re.compile(r"FIRECRACKER_P5_READY counter=(\d+)")
HB_RE=re.compile(r"FIRECRACKER_P5_HEARTBEAT counter=(\d+)")

def _read_status(state_dir:pathlib.Path)->dict:
    state=json.loads((state_dir/"state.json").read_text())
    log=(state_dir/"vm.log").read_text(errors="ignore") if (state_dir/"vm.log").exists() else ""
    hbs=[int(x) for x in HB_RE.findall(log)]
    pid=state.get("firecracker_pid")
    alive=bool(pid and pathlib.Path(f"/proc/{pid}").exists())
    return {
        "role":state["role"],"alive":alive,"firecracker_pid":pid,
        "ready_observed":bool(READY_RE.search(log)),
        "last_heartbeat_counter":max(hbs) if hbs else None,
        "host_fingerprint":state["host_fingerprint"],
        "portable":state["portable"],
        "start_lifecycle_timing":state["start_lifecycle_timing"],
    }

def start(role:str,state_dir:pathlib.Path)->dict:
    timer=LifecycleTimer(); state_dir.mkdir(parents=True,exist_ok=True)
    vm=f1._load_json(p3.VMM_MANIFEST); km=f1._load_json(p3.KERNEL_MANIFEST)
    archive=state_dir/"firecracker.tgz"; extract=state_dir/"vmm"; extract.mkdir(exist_ok=True)
    kernel=state_dir/"vmlinux"; init_bin=state_dir/"init"; initrd=state_dir/"initrd.cpio"
    config_path=state_dir/"vm-config.json"; sock=state_dir/"vm.sock"; log_path=state_dir/"vm.log"
    with timer.stage("vmm_download_and_verify","venue"):
        vv=f1._download_and_verify(vm["archive_url"],vm["archive_sha256"],archive)
    with timer.stage("vmm_extract","portable"):
        f0._safe_extract(archive,extract); fc=f1._find_firecracker(extract,vm["version"],vm["architecture"])
    with timer.stage("kernel_download_and_verify","venue"):
        kv=f1._download_and_verify(km["kernel_url"],km["kernel_sha256"],kernel)
    with timer.stage("guest_init_compile","portable"):
        ic=f1._compile_init(INIT_SOURCE,init_bin)
    if not vv["verified"] or not kv["verified"] or not ic["ok"]: raise RuntimeError("P5 build prerequisite failed")
    with timer.stage("initramfs_build","portable"): p3._build_initramfs(init_bin,initrd)
    with timer.stage("vm_config_build","portable"): config=f1._build_config(kernel,initrd,config_path)

    sudo=shutil.which("sudo")
    if not sudo: raise RuntimeError("sudo unavailable")
    with timer.stage("process_start_to_ready","portable"):
        logfh=log_path.open("w")
        proc=subprocess.Popen([sudo,"-n",str(fc.resolve()),"--api-sock",str(sock.resolve()),"--config-file",str(config_path.resolve())],
                              stdout=logfh,stderr=subprocess.STDOUT,text=True,start_new_session=True)
        logfh.close()
        deadline=time.monotonic()+7
        ready=False; hb=False
        while time.monotonic()<deadline:
            text=log_path.read_text(errors="ignore") if log_path.exists() else ""
            ready=bool(READY_RE.search(text)); hb=bool(HB_RE.search(text))
            if ready and hb: break
            if proc.poll() is not None: break
            time.sleep(.05)
        if not (ready and hb):
            try: proc.terminate()
            except OSError: pass
            raise RuntimeError("P5 guest did not reach READY+heartbeat")
    pid=p3._actual_firecracker_pid(sock)
    state={
        "schema":"firecracker-p5-vm-state/v1","role":role,"wrapper_pid":proc.pid,"firecracker_pid":pid,
        "host_fingerprint":fingerprint(),
        "portable":{"vmm_version":vm["version"],"vmm_sha256":vv["actual_sha256"],"kernel_version":km["kernel_version"],
                    "kernel_sha256":kv["actual_sha256"],"guest_init_binary_sha256":f1._sha256(init_bin),
                    "initrd_sha256":f1._sha256(initrd),"machine":{"vcpu_count":config["machine-config"]["vcpu_count"],
                    "mem_size_mib":config["machine-config"]["mem_size_mib"],"drives":0,"network_interfaces":0}},
        "start_lifecycle_timing":timer.receipt(),
    }
    (state_dir/"state.json").write_text(json.dumps(state,indent=2,sort_keys=True)+"\n")
    return _read_status(state_dir)

def stop(state_dir:pathlib.Path)->dict:
    before=_read_status(state_dir); pid=before.get("firecracker_pid"); started=time.perf_counter()
    if pid and pathlib.Path(f"/proc/{pid}").exists():
        subprocess.run(["sudo","-n","kill","-TERM",str(pid)],check=False,capture_output=True,text=True)
        deadline=time.monotonic()+3
        while time.monotonic()<deadline and pathlib.Path(f"/proc/{pid}").exists(): time.sleep(.05)
        if pathlib.Path(f"/proc/{pid}").exists():
            subprocess.run(["sudo","-n","kill","-KILL",str(pid)],check=False,capture_output=True,text=True)
    after=_read_status(state_dir)
    return {"before":before,"after":after,"stop_elapsed_ms":round((time.perf_counter()-started)*1000,3)}

def main()->int:
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("start"); a.add_argument("--role",required=True); a.add_argument("--state-dir",type=pathlib.Path,required=True); a.add_argument("--out",type=pathlib.Path,required=True)
    b=sub.add_parser("status"); b.add_argument("--state-dir",type=pathlib.Path,required=True); b.add_argument("--out",type=pathlib.Path,required=True)
    d=sub.add_parser("stop"); d.add_argument("--state-dir",type=pathlib.Path,required=True); d.add_argument("--out",type=pathlib.Path,required=True)
    x=p.parse_args(); x.out.parent.mkdir(parents=True,exist_ok=True)
    try:
        result=start(x.role,x.state_dir) if x.cmd=="start" else _read_status(x.state_dir) if x.cmd=="status" else stop(x.state_dir)
        rc=0
    except Exception as e: result={"classification":"HARNESS_FAILURE","reason":f"{type(e).__name__}: {e}"}; rc=1
    x.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n"); print(json.dumps(result,indent=2,sort_keys=True)); return rc
if __name__=="__main__": raise SystemExit(main())
