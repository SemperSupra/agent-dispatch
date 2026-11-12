#!/usr/bin/env python3
"""R61 synthetic PID-namespace init teardown capability on disposable public Linux GHA.

Host-side observer executes as root only inside a disposable GitHub Actions runner.
Namespace init and descendants run unprivileged, with no private source/media.
"""
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

def status_state(pid):
    try:
        stat=(Path("/proc") / str(pid) / "stat").read_text().split()
        return stat[2] if len(stat)>2 else "?"
    except (FileNotFoundError,ProcessLookupError,PermissionError):
        return "X"

def members(ns):
    results=[]
    for p in Path("/proc").iterdir():
        if not p.name.isdecimal():continue
        pid=int(p.name)
        try:
            if os.readlink(p/"ns"/"pid")==ns and status_state(pid) not in ("X","Z"):
                results.append(pid)
        except (FileNotFoundError,ProcessLookupError,PermissionError):
            pass
    return results

def ns_init(path,host_pidns,host_netns):
    if os.getpid()!=1:raise RuntimeError("R61_IS_NOT_PID_NAMESPACE_INIT")
    pns=os.readlink("/proc/self/ns/pid")
    nns=os.readlink("/proc/self/ns/net")
    if pns==host_pidns or nns==host_netns:raise RuntimeError("R61_NAMESPACE_NOT_ISOLATED")
    if (os.geteuid(),os.getegid())!=(65534,65534):raise RuntimeError("R61_PRIVILEGE_DROP")
    cap=[x.split()[1] for x in Path("/proc/self/status").read_text().splitlines() if x.startswith("CapEff:")]
    if len(cap)!=1 or int(cap[0],16)!=0:raise RuntimeError("R61_EFFECTIVE_CAPS_NOT_ZERO")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(.25)
        e=s.connect_ex(("192.0.2.1",443))
    if e not in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES):
        raise RuntimeError("R61_NETWORK_ROUTE_UNEXPECTED")
    # Simulate an uncooperative, detached downloader descendant; independent
    # process group cannot evade whole PID-namespace shutdown.
    child=subprocess.Popen(["/bin/sleep","30"],start_new_session=True,
                           stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,close_fds=True)
    (path/"pid_namespace").write_text(pns+"\n")
    (path/"child_pid_inside").write_text(str(child.pid)+"\n")
    (path/"ns_init_ready").write_text("ready\n")
    while True:time.sleep(.1)

def await_path(p,spawn):
    deadline=time.monotonic()+4
    while not p.is_file():
        if spawn.poll() is not None:
            detail = spawn.stderr.read(2048).decode("utf-8", "replace").strip()
            raise RuntimeError("R61_INIT_NOT_READY:%s stderr=%s" % (spawn.returncode, detail))
        if time.monotonic()>=deadline:
            raise RuntimeError("R61_INIT_NOT_READY_TIMEOUT")
        time.sleep(.015)

def kill_checked(pid):
    try: os.kill(pid,signal.SIGKILL)
    except ProcessLookupError: pass

def trial(root,rep):
    stage=root/("rep-%d"%rep)
    stage.mkdir(mode=0o777)
    stage.chmod(0o777)  # os.mkdir respects root umask; namespace uid65534 must write
    host_pidns=os.readlink("/proc/self/ns/pid")
    host_netns=os.readlink("/proc/self/ns/net")
    cmd=["unshare","--mount","--pid","--fork","--mount-proc","--net",
         "--propagation","private","--","setpriv","--reuid=65534",
         "--regid=65534","--clear-groups",sys.executable,"-B",__file__,
         "init",str(stage),host_pidns,host_netns]
    wrapper=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
    ns=None
    init_host_pid=None
    try:
        await_path(stage/"ns_init_ready",wrapper)
        ns=(stage/"pid_namespace").read_text().strip()
        if ns==host_pidns or not ns.startswith("pid:["):raise RuntimeError("R61_PIDNS_INVALID")
        found=members(ns)
        # The init and a setsid detached sleeper must both be accounted for
        # inside the namespace before shutdown.
        if len(found)<2:raise RuntimeError("R61_DETACHED_CHILD_NOT_VISIBLE")
        for p in found:
            try:
                line=next(l for l in (Path("/proc")/str(p)/"status").read_text().splitlines() if l.startswith("NSpid:"))
                nspid=[int(t) for t in line.split()[1:]]
                if nspid and nspid[-1]==1:init_host_pid=p
            except (FileNotFoundError,StopIteration,PermissionError):
                pass
        if not init_host_pid:raise RuntimeError("R61_NAMESPACE_INIT_HOST_PID_NOT_FOUND")
        if status_state(init_host_pid) in ("X","Z"):raise RuntimeError("R61_INIT_DIED_PREMATURELY")
        kill_checked(init_host_pid)
        end=time.monotonic()+3
        while time.monotonic()<end and members(ns):
            time.sleep(.025)
        if members(ns):
            raise RuntimeError("R61_PIDNS_INIT_DEATH_LEAKED_PROCESSES")
        try:
            wrapper.wait(timeout=3)
        except subprocess.TimeoutExpired:
            raise RuntimeError("R61_WRAPPER_DID_NOT_EXIT")
        return {"rep":rep,"pid_namespace_separate":True,
                "before_kill_live_members_at_least_two":True,
                "detached_setsid_child_alive_before":True,
                "namespace_init_killed":True,"all_namespace_processes_gone":True,
                "cleanup_pass":True}
    finally:
        if ns:
            for pid in members(ns):kill_checked(pid)
        if wrapper.poll() is None:
            try:os.killpg(wrapper.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            wrapper.kill()
        try:wrapper.communicate(timeout=3)
        except subprocess.TimeoutExpired:pass
        for p in stage.iterdir():
            if not p.is_file() or p.is_symlink():raise RuntimeError("R61_UNSAFE_STAGE_FILE")
            p.unlink()
        stage.rmdir()

def main():
    if len(sys.argv)==5 and sys.argv[1]=="init":
        ns_init(Path(sys.argv[2]),sys.argv[3],sys.argv[4])
        return
    if len(sys.argv)!=2:raise RuntimeError("R61_ARGUMENTS_INVALID")
    if os.geteuid()!=0:raise RuntimeError("R61_HOST_OBSERVER_REQUIRES_RUNNER_ROOT")
    root=Path(sys.argv[1]).resolve()
    results=[trial(root,rep) for rep in range(3)]
    if len(results)!=3 or list(root.iterdir()):raise RuntimeError("R61_REPS_OR_CLEANUP")
    report={"scope":"PUBLIC_SYNTHETIC_LINUX_PID_NAMESPACE_TEARDOWN_ONLY",
            "arch":os.uname().machine,"reps":3,"cases":results,
            "private_winnow_source":False,"actual_vendor_extractor":False,
            "production_sandbox_integrated":False,
            "cgroup_memory_cpu_io_qualified":False,
            "sandbox_escape_resistance_qualified":False,
            "bigmac_or_truenas_qualified":False,
            "source_rights":"HOLD","release":"HOLD"}
    print(json.dumps(report,sort_keys=True),flush=True)
    print("R61_PIDNS_INIT_TEARDOWN_SYNTHETIC_PASS arch=%s reps=3 product=NOT_RUN"%report["arch"],flush=True)

if __name__=="__main__":main()
