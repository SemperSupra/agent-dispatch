#!/usr/bin/env python3
"""R65 synthetic advisory reader-lease/GC exclusion; local filesystems only."""
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

def signal(path):
    path.write_text("ready\n")

def spin(path, procs, secs=4):
    end=time.monotonic()+secs
    while not path.exists():
        if time.monotonic()>end or any(p.poll() not in (None,0) for p in procs):
            raise RuntimeError("R65_CHILD_OR_BARRIER_FAILURE:"+path.name)
        time.sleep(.012)

def reader(root, name):
    with open(root/"generation.lock","rb") as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_SH)
        if not (root/"retired.bin").is_file():
            raise RuntimeError("R65_READER_LOST_RETIRED_GENERATION")
        signal(root/("reader-"+name+"-ready"))
        deadline=time.monotonic()+5
        while not (root/("release-"+name)).exists():
            if time.monotonic()>deadline:
                raise RuntimeError("R65_READER_STALLED")
            time.sleep(.012)
        if not (root/"retired.bin").is_file():
            raise RuntimeError("R65_GC_RAN_UNDER_READER_LEASE")
        fcntl.flock(lock.fileno(),fcntl.LOCK_UN)

def gc(root):
    signal(root/"gc-attempted")
    with open(root/"generation.lock","rb") as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        if not (root/"retired.bin").is_file() or not (root/"current.bin").is_file():
            raise RuntimeError("R65_WRONG_GENERATION_STATE")
        (root/"retired.bin").unlink()
        signal(root/"gc-completed")
        fcntl.flock(lock.fileno(),fcntl.LOCK_UN)

def child(root, role, name=None):
    if role=="reader": reader(root,name)
    elif role=="gc":gc(root)
    else:raise RuntimeError("R65_UNKNOWN_CHILD")

def test(work,rep,mode):
    root=work/("rep-%d-%s"%(rep,mode))
    root.mkdir(mode=0o700)
    (root/"generation.lock").write_bytes(b"lease\n")
    (root/"retired.bin").write_bytes(b"old complete synthetic bytes")
    (root/"current.bin").write_bytes(b"current complete synthetic bytes")
    runners=[]
    args=lambda *a:[sys.executable,"-B",__file__,"child",str(root),*a]
    try:
        a=subprocess.Popen(args("reader","a"),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,close_fds=True)
        b=subprocess.Popen(args("reader","b"),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,close_fds=True)
        runners.extend([a,b])
        spin(root/"reader-a-ready",[a,b]);spin(root/"reader-b-ready",[a,b])
        g=subprocess.Popen(args("gc"),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,close_fds=True)
        runners.append(g)
        spin(root/"gc-attempted",runners)
        time.sleep(.075)
        if (root/"gc-completed").exists():
            raise RuntimeError("R65_GC_STARTED_WHILE_TWO_READERS_ACTIVE")
        if mode=="crashed-reader":
            a.kill()
            a.wait(timeout=3)
        else:
            signal(root/"release-a")
            if a.wait(timeout=3)!=0:raise RuntimeError("R65_READER_A_EXIT_FAILURE")
        time.sleep(.075)
        if (root/"gc-completed").exists():
            raise RuntimeError("R65_GC_STARTED_WITH_READER_B_ACTIVE")
        signal(root/"release-b")
        if b.wait(timeout=3)!=0:raise RuntimeError("R65_READER_B_EXIT_FAILURE")
        spin(root/"gc-completed",[g])
        if g.wait(timeout=3)!=0:raise RuntimeError("R65_GC_EXIT_FAILURE")
        if (root/"retired.bin").exists() or (root/"current.bin").read_bytes()!=b"current complete synthetic bytes":
            raise RuntimeError("R65_GC_REMOVED_WRONG_GENERATION")
        return {"rep":rep,"mode":mode,"concurrent_readers":2,
                "gc_blocked_until_all_readers_exit":True,
                "crash_released_shared_lease":mode=="crashed-reader",
                "current_generation_intact":True,"scratch_cleanup":True}
    finally:
        for p in runners:
            if p.poll() is None:p.kill()
            p.wait(timeout=3)
            if p.stderr:p.stderr.close()
        for path in root.iterdir():
            if not path.is_file() or path.is_symlink():
                raise RuntimeError("R65_UNSAFE_STAGE")
            path.unlink()
        root.rmdir()
        if root.exists():raise RuntimeError("R65_CLEANUP_FAILED")

def main():
    if len(sys.argv)==5 and sys.argv[1]=="child":
        child(Path(sys.argv[2]),sys.argv[3],sys.argv[4])
        return
    if len(sys.argv)==4 and sys.argv[1]=="child":
        child(Path(sys.argv[2]),sys.argv[3])
        return
    if len(sys.argv)!=3:raise RuntimeError("R65_ARGS")
    host_ns, path=sys.argv[1:]
    if os.readlink("/proc/self/ns/net")==host_ns:
        raise RuntimeError("R65_NETWORK_NS_UNSEPARATED")
    if (os.geteuid(),os.getegid())!=(65534,65534):
        raise RuntimeError("R65_NOT_UNPRIVILEGED")
    cap=[x.split()[1] for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("CapEff:")]
    if len(cap)!=1 or int(cap[0],16)!=0:raise RuntimeError("R65_CAPS_NOT_ZERO")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.settimeout(.2)
        e=sock.connect_ex(("192.0.2.1",443))
    if e not in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES):
        raise RuntimeError("R65_EGRESS_DENIAL_MISSING")
    work=Path(path).resolve()
    cases=[test(work,rep,mode) for rep in range(3) for mode in ("normal","crashed-reader")]
    if len(cases)!=6 or list(work.iterdir()):raise RuntimeError("R65_REPS_OR_CLEANUP")
    result={"scope":"PUBLIC_SYNTHETIC_LOCAL_READER_LEASE_GC_ONLY",
            "arch":os.uname().machine,"reps_per_case":3,"cases":cases,
            "multi_host_distributed_lease_qualified":False,
            "power_failure_durability_qualified":False,
            "filesystem_race_hardening_qualified":False,
            "private_winnow_source":False,"product_integrated":False,
            "live_media_requests":0,"release":"HOLD"}
    print(json.dumps(result,sort_keys=True),flush=True)
    print("R65_LOCAL_READER_GC_LEASE_PASS arch=%s cases=6 product=NOT_RUN"%result["arch"],flush=True)

if __name__=="__main__":main()
