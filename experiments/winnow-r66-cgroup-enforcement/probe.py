#!/usr/bin/env python3
"""R66 public-only native cgroup v2 kernel pids and memory hard-denial witness."""
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

CGROOT=Path("/sys/fs/cgroup")
WANTED={"cpu","pids","memory"}

def kernel_events(path,filename,key):
    values={}
    for line in (path/filename).read_text().splitlines():
        bits=line.split()
        if len(bits)==2:values[bits[0]]=int(bits[1])
    return values.get(key,0)

def worker(group,mode):
    # Move ONLY this synthetic worker and its descendants into the scoped cgroup.
    (group/"cgroup.procs").write_text(str(os.getpid()))
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    if mode=="pids":
        children=[]
        denied=False
        try:
            for _ in range(12):
                try:
                    p=subprocess.Popen(["/bin/sleep","30"],stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                       close_fds=True)
                    children.append(p)
                except OSError as e:
                    if e.errno!=errno.EAGAIN:raise
                    denied=True
                    break
            if not denied or len(children)!=3:
                raise RuntimeError("R66_PIDS_LIMIT_NOT_ENFORCED")
            print("R66_PID_WORKER_EAGAIN expected=3",flush=True)
        finally:
            for p in children:
                if p.poll() is None:p.kill()
                p.wait(timeout=3)
        return
    if mode=="memory":
        # This must be killed by the cgroup's memory.max, not Python MemoryError.
        data=bytearray(512<<20)
        for i in range(0,len(data),4096):
            data[i]=1
        print("R66_MEMORY_NOT_DENIED",flush=True)
        raise RuntimeError("R66_KERNEL_MEMORY_MAX_NOT_ENFORCED")
    raise RuntimeError("R66_BAD_MODE")

def reap_cgroup(group):
    try:
        (group/"cgroup.kill").write_text("1")
    except OSError:
        pass
    deadline=time.monotonic()+2
    while time.monotonic()<deadline:
        try:
            if not (group/"cgroup.procs").read_text().strip():return True
        except FileNotFoundError:
            return True
        time.sleep(.025)
    return False

def trial(root,mode,rep):
    cg=root/("r66-%s-%s-%d"%(os.getpid(),mode,rep))
    cg.mkdir(mode=0o700)
    try:
        key="pids.max" if mode=="pids" else "memory.max"
        bound="4" if mode=="pids" else str(64<<20)
        (cg/key).write_text(bound)
        if (cg/key).read_text().strip()!=bound:
            raise RuntimeError("R66_CONTROLLER_WRITE_MISMATCH")
        args=[sys.executable,"-B",__file__,"worker",str(cg),mode]
        proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
        try:
            out,err=proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGKILL)
            out,err=proc.communicate(timeout=3)
            raise RuntimeError("R66_WORKER_TIMEOUT")
        if mode=="pids":
            if proc.returncode!=0 or b"R66_PID_WORKER_EAGAIN" not in out:
                raise RuntimeError("R66_PID_NEGATIVE_FAILED exit=%s stderr=%s"%(proc.returncode,err.decode(errors="replace")[:150]))
            count=kernel_events(cg,"pids.events","max")
            if count<1:raise RuntimeError("R66_PID_KERNEL_EVENT_MISSING")
        else:
            if proc.returncode!=-signal.SIGKILL:
                raise RuntimeError("R66_MEMORY_NOT_KERNEL_KILLED exit=%s stderr=%s"%(proc.returncode,err.decode(errors="replace")[:120]))
            count=kernel_events(cg,"memory.events","oom_kill")
            if count<1:raise RuntimeError("R66_OOM_KILL_EVENT_MISSING")
        return {"mode":mode,"rep":rep,"worker_exit":proc.returncode,
                "limit":int(bound),"kernel_denial_events":count,
                "actual_kernel_enforcement_observed":True}
    finally:
        if not reap_cgroup(cg):raise RuntimeError("R66_CGROUP_PROCESSES_NOT_CLEAN")
        cg.rmdir()
        if cg.exists():raise RuntimeError("R66_CGROUP_TEARDOWN_FAILED")

def main():
    if len(sys.argv)==4 and sys.argv[1]=="worker":
        worker(Path(sys.argv[2]),sys.argv[3])
        return
    if len(sys.argv)!=2:raise RuntimeError("R66_BAD_ARGS")
    if os.geteuid()!=0:raise RuntimeError("R66_REQUIRES_DISPOSABLE_RUNNER_ROOT")
    hostns=sys.argv[1]
    if os.readlink("/proc/self/ns/net")==hostns:
        raise RuntimeError("R66_NET_NAMESPACE_UNSEPARATED")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(.3)
        e=s.connect_ex(("192.0.2.1",443))
    if e not in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES):
        raise RuntimeError("R66_KERNEL_EGRESS_DENIAL_MISSING")
    if not WANTED.issubset((CGROOT/"cgroup.controllers").read_text().split()):
        raise RuntimeError("R66_CONTROLLER_MISSING")
    if not WANTED.issubset((CGROOT/"cgroup.subtree_control").read_text().split()):
        raise RuntimeError("R66_CONTROLLER_NOT_DELEGATED")
    results=[trial(CGROOT,mode,rep) for rep in range(3) for mode in ("pids","memory")]
    if len(results)!=6:raise RuntimeError("R66_REPS_INVALID")
    report={"scope":"PUBLIC_SYNTHETIC_LINUX_CGROUP_V2_PID_MEMORY_KERNEL_DENIAL",
            "arch":os.uname().machine,"reps_per_case":3,"cases":results,
            "cpu_quota_enforcement_qualified":False,
            "io_quota_enforcement_qualified":False,
            "private_winnow_code_used":False,"real_vendor_extractor":False,
            "product_runtime_integrated":False,"target_platform_qualified":False,
            "source_rights":"HOLD","release":"HOLD"}
    print(json.dumps(report,sort_keys=True),flush=True)
    print("R66_CGROUP_KERNEL_PID_MEMORY_DENIAL_PASS arch=%s cases=6 product=NOT_RUN"%report["arch"],flush=True)

if __name__=="__main__":main()
