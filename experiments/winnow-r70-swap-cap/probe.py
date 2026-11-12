#!/usr/bin/env python3
"""R70 public synthetic cgroup memory charge / OOM differential."""
import errno,json,mmap,os,signal,socket,subprocess,sys,time
from pathlib import Path
ROOT=Path("/sys/fs/cgroup")
MB=1048576
def events(group):
    result={}
    for line in (group/"memory.events").read_text().splitlines():
        k,v=line.split()
        result[k]=int(v)
    return result
def worker(group,mode):
    (group/"cgroup.procs").write_text(str(os.getpid()))
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    print("R70_WORKER_JOINED "+Path("/proc/self/cgroup").read_text().strip(),flush=True)
    amount=(16 if mode=="control" else 192)*MB
    with mmap.mmap(-1,amount,access=mmap.ACCESS_WRITE) as mem:
        for i in range(0,amount,4096):
            mem[i:i+1]=b"x"
    print("R70_WORKER_FINISHED mode=%s bytes=%d"%(mode,amount),flush=True)
    return 0 if mode=="control" else 17
def trial(mode,rep):
    group=ROOT/("winnow-r70-%s-%s-%d"%(os.getpid(),mode,rep))
    group.mkdir()
    try:
        (group/"memory.max").write_text(str(64*MB))
        (group/"memory.swap.max").write_text("0")
        if (group/"memory.swap.max").read_text().strip()!="0":
            raise RuntimeError("R70_SWAP_DENIAL_NOT_CONFIGURED")
        if (group/"memory.max").read_text().strip()!=str(64*MB):
            raise RuntimeError("R70_LIMIT_WRITEBACK_MISMATCH")
        old=events(group)
        p=subprocess.Popen([sys.executable,"-B",__file__,"worker",str(group),mode],
                           stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           start_new_session=True,close_fds=True)
        try:
            out,err=p.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGKILL)
            p.communicate(timeout=3)
            raise RuntimeError("R70_TIMEOUT")
        newer=events(group)
        killed=newer.get("oom_kill",0)-old.get("oom_kill",0)
        peak=(group/"memory.peak").read_text().strip() if (group/"memory.peak").exists() else "UNAVAILABLE"
        observed={"mode":mode,"rep":rep,"exit":p.returncode,"oom_kill_events":killed,
                  "swap_max_bytes":(group/"memory.swap.max").read_text().strip(),
                  "swap_peak_bytes":(group/"memory.swap.peak").read_text().strip() if (group/"memory.swap.peak").exists() else "UNAVAILABLE",
                  "peak_bytes":peak,"worker_joined":b"R70_WORKER_JOINED" in out}
        if mode=="control":
            if p.returncode!=0 or not observed["worker_joined"] or b"R70_WORKER_FINISHED" not in out:
                raise RuntimeError("R70_POSITIVE_CONTROL_FAILED "+json.dumps(observed)+" "+err.decode(errors="replace")[:300])
        else:
            if p.returncode!=-signal.SIGKILL or killed<1 or not observed["worker_joined"]:
                raise RuntimeError("R70_MMAP_MEMORY_HARD_DENIAL_NOT_PROVEN "+json.dumps(observed)+" stdout="+out.decode(errors="replace")[:200]+" stderr="+err.decode(errors="replace")[:350])
        return observed
    finally:
        if group.exists():
            try:
                (group/"cgroup.kill").write_text("1")
            except OSError: pass
            for _ in range(60):
                if not (group/"cgroup.procs").read_text().strip():
                    break
                time.sleep(.02)
            if (group/"cgroup.procs").read_text().strip(): raise RuntimeError("R70_LEAKED_CGROUP_MEMBERS")
            group.rmdir()
def main():
    if len(sys.argv)==4 and sys.argv[1]=="worker":sys.exit(worker(Path(sys.argv[2]),sys.argv[3]))
    if len(sys.argv)!=2 or os.geteuid()!=0:raise RuntimeError("R70_DISPOSABLE_ROOT_ARGS_INVALID")
    if os.readlink("/proc/self/ns/net")==sys.argv[1]:raise RuntimeError("R70_NETNS_NOT_ISOLATED")
    if "memory" not in (ROOT/"cgroup.subtree_control").read_text().split():raise RuntimeError("R70_MEMORY_CONTROLLER_NOT_DELEGATED")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.settimeout(.2)
        code=sock.connect_ex(("192.0.2.1",443))
        if code not in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES):raise RuntimeError("R70_EGRESS_NOT_DENIED")
    results=[]
    for rep in range(3):
        for mode in ("control","mmap"):
            result=trial(mode,rep)
            results.append(result)
            print("R70_CASE_OK "+json.dumps(result,sort_keys=True),flush=True)
    print(json.dumps({"scope":"PUBLIC_SYNTHETIC_CGROUP_MEMORY_MMAP_ONLY","arch":os.uname().machine,"cases":results,
                      "private_source":False,"production_sandbox":False,"cpu_io_enforced":False,
                      "source_rights":"HOLD","release":"HOLD"},sort_keys=True),flush=True)
    print("R70_NATIVE_MEMCG_MMAP_DENIAL_PASS arch=%s cases=6 product=NOT_RUN"%os.uname().machine,flush=True)
if __name__=="__main__":main()
