#!/usr/bin/env python3
"""R62 public synthetic local filesystem flock protects generation-pointer writers."""
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

def atomic_json(path, data):
    candidate = path.with_name(path.name + ".tmp." + str(os.getpid()))
    with open(candidate, "x", encoding="utf-8") as f:
        json.dump(data, f, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(candidate, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def visible(root):
    name = json.loads((root / "current.json").read_text())["generation"]
    data = json.loads((root / "gens" / name / "records.json").read_text())
    if data.get("generation") != name or not isinstance(data.get("members"), list):
        raise RuntimeError("R62_INVALID_POINTER_GENERATION")
    return name, data["members"]

def signal_file(root, name):
    (root / name).write_text("ready\n")

def await_file(root, name, deadline=4):
    end = time.monotonic() + deadline
    while not (root / name).exists():
        if time.monotonic() >= end:
            raise RuntimeError("R62_BARRIER_TIMEOUT_" + name)
        time.sleep(.01)

def writer(root, name, crash):
    signal_file(root, "attempt-" + name)
    with open(root / "writer.lock", "a+b", buffering=0) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        old, members = visible(root)
        if name in members:
            raise RuntimeError("R62_DUPLICATE_WRITER")
        new = name + "-" + old
        generation = root / "gens" / new
        generation.mkdir(mode=0o700)
        atomic_json(generation / "records.json", {"generation": new, "members": members + [name]})
        signal_file(root, "acquired-" + name)
        if name == "a":
            await_file(root, "allow-a")
        if crash:
            os._exit(77)
        atomic_json(root / "current.json", {"generation": new})
        signal_file(root, "committed-" + name)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

def wait(path, procs):
    end = time.monotonic() + 4
    while not path.exists():
        if time.monotonic() >= end or any(p.poll() not in (None, 0) for p in procs):
            raise RuntimeError("R62_PROCESS_OR_BARRIER_FAILURE_" + path.name)
        time.sleep(.01)

def trial(work, mode, rep):
    root = work / ("rep-%d-%s" % (rep, mode))
    (root / "gens" / "base").mkdir(parents=True, mode=0o700)
    atomic_json(root / "gens" / "base" / "records.json", {"generation": "base", "members": []})
    atomic_json(root / "current.json", {"generation": "base"})
    args = lambda name, crash: [sys.executable, "-B", __file__, "writer", str(root), name, "crash" if crash else "ok"]
    a = subprocess.Popen(args("a", mode=="crash"), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    b = None
    try:
        wait(root / "acquired-a", [a])
        b = subprocess.Popen(args("b", False), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        wait(root / "attempt-b", [a,b])
        # B has attempted, but cannot read an intermediate or commit while A's
        # held lock guards the whole read/stage/pointer transaction.
        time.sleep(.08)
        if (root / "acquired-b").exists():
            raise RuntimeError("R62_LOCK_DID_NOT_EXCLUDE_SECOND_WRITER")
        (root / "allow-a").touch()
        if mode == "normal":
            wait(root / "committed-a", [a,b])
        else:
            if a.wait(timeout=3) != 77:
                raise RuntimeError("R62_INJECTED_CRASH_MISSING")
        # In crash mode A intentionally exited 77; only B remains pending.
        wait(root / "committed-b", [b])
        if a.wait(timeout=3) != (77 if mode=="crash" else 0) or b.wait(timeout=3) != 0:
            raise RuntimeError("R62_WRITER_EXIT_UNEXPECTED")
        generation, members = visible(root)
        expected = ["b"] if mode=="crash" else ["a","b"]
        if members != expected:
            raise RuntimeError("R62_LOST_OR_FALSELY_COMMITTED_UPDATE:%r" % members)
        if mode == "crash" and not (root / "gens" / "a-base" / "records.json").is_file():
            raise RuntimeError("R62_PRECOMMIT_ORPHAN_WITNESS_MISSING")
        return {"mode": mode, "rep": rep, "both_writers_started": True,
                "exclusive_lock_observed": True, "visible_members": members,
                "a_crash_released_kernel_lock": mode=="crash", "cleaned": True}
    finally:
        for p in (a,b):
            if p is not None:
                if p.poll() is None:
                    p.kill()
                p.wait(timeout=3)
        for p in sorted(root.rglob("*"), key=lambda x:len(x.parts), reverse=True):
            if p.is_symlink(): raise RuntimeError("R62_UNSAFE_SYMLINK")
            if p.is_file(): p.unlink()
            elif p.is_dir(): p.rmdir()
        root.rmdir()
        if root.exists(): raise RuntimeError("R62_CLEANUP_FAILED")

def main():
    if len(sys.argv)==5 and sys.argv[1]=="writer":
        writer(Path(sys.argv[2]),sys.argv[3],sys.argv[4]=="crash")
        return
    if len(sys.argv)!=3: raise RuntimeError("R62_ARGS_INVALID")
    host_ns, path = sys.argv[1:]
    if os.readlink("/proc/self/ns/net")==host_ns: raise RuntimeError("R62_NETNS_UNSEPARATED")
    if (os.geteuid(),os.getegid())!=(65534,65534): raise RuntimeError("R62_PRIVILEGE_DROP")
    cap=[s.split()[1] for s in Path("/proc/self/status").read_text().splitlines() if s.startswith("CapEff:")]
    if len(cap)!=1 or int(cap[0],16)!=0: raise RuntimeError("R62_CAPS_NOT_ZERO")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(.2)
        e=s.connect_ex(("192.0.2.1",443))
    if e not in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES): raise RuntimeError("R62_NET_DENIAL")
    work=Path(path).resolve()
    cases=[trial(work,mode,rep) for rep in range(3) for mode in ("normal","crash")]
    if len(cases)!=6 or list(work.iterdir()):raise RuntimeError("R62_CLEANUP_OR_REPS")
    report={"scope":"PUBLIC_SYNTHETIC_LOCAL_FLOCK_GENERATION_WRITER_ONLY",
            "arch":os.uname().machine,"reps_per_case":3,"cases":cases,
            "multi_host_or_nfs_locking_qualified":False,
            "concurrent_reader_gc_qualified":False,
            "power_loss_durability_qualified":False,
            "private_winnow_source":False,"production_recovery_implemented":False,
            "source_rights":"HOLD","release":"HOLD"}
    print(json.dumps(report,sort_keys=True),flush=True)
    print("R62_LOCAL_FLOCK_WRITER_SYNTHETIC_PASS arch=%s cases=6 product=NOT_RUN" % report["arch"],flush=True)

if __name__=="__main__":main()
