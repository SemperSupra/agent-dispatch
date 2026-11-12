#!/usr/bin/env python3
"""R71 public synthetic cgroup memory charge / OOM differential."""
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
    print("R71_WORKER_JOINED "+Path("/proc/self/cgroup").read_text().strip(),flush=True)
    amount=(16 if mode=="control" else 192)*MB
    with mmap.mmap(-1,amount,access=mmap.ACCESS_WRITE) as mem:
        for i in range(0,amount,4096):
            mem[i:i+1]=b"x"
    print("R71_WORKER_FINISHED mode=%s bytes=%d"%(mode,amount),flush=True)
    return 0 if mode=="control" else 17
def trial(mode,rep,swap_mode):
    group=ROOT/("winnow-r71-%s-%s-%s-%d"%(os.getpid(),swap_mode,mode,rep))
    group.mkdir()
    try:
        (group/"memory.max").write_text(str(64*MB))
        swap_limit="0" if swap_mode=="off" else "max"
        (group/"memory.swap.max").write_text(swap_limit)
        if (group/"memory.swap.max").read_text().strip()!=swap_limit:
            raise RuntimeError("R71_SWAP_DENIAL_NOT_CONFIGURED")
        if (group/"memory.max").read_text().strip()!=str(64*MB):
            raise RuntimeError("R71_LIMIT_WRITEBACK_MISMATCH")
        old=events(group)
        p=subprocess.Popen([sys.executable,"-B",__file__,"worker",str(group),mode],
                           stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           start_new_session=True,close_fds=True)
        try:
            out,err=p.communicate(timeout=12)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGKILL)
            p.communicate(timeout=3)
            raise RuntimeError("R71_TIMEOUT")
        newer=events(group)
        killed=newer.get("oom_kill",0)-old.get("oom_kill",0)
        peak=(group/"memory.peak").read_text().strip() if (group/"memory.peak").exists() else "UNAVAILABLE"
        observed={"mode":mode,"rep":rep,"swap_mode":swap_mode,"exit":p.returncode,"oom_kill_events":killed,
                  "swap_max_bytes":(group/"memory.swap.max").read_text().strip(),
                  "swap_peak_bytes":(group/"memory.swap.peak").read_text().strip() if (group/"memory.swap.peak").exists() else "UNAVAILABLE",
                  "peak_bytes":peak,"worker_joined":b"R71_WORKER_JOINED" in out}
        if mode=="control":
            if p.returncode!=0 or not observed["worker_joined"] or b"R71_WORKER_FINISHED" not in out:
                raise RuntimeError("R71_POSITIVE_CONTROL_FAILED "+json.dumps(observed)+" "+err.decode(errors="replace")[:300])
        else:
            killed_by_kernel=p.returncode==-signal.SIGKILL and killed>=1
            swapped_to_complete=(swap_mode=="available" and p.returncode==17 and
                b"R71_WORKER_FINISHED" in out and observed["swap_peak_bytes"]!="UNAVAILABLE" and
                int(observed["swap_peak_bytes"])>0)
            if not observed["worker_joined"] or (swap_mode=="off" and not killed_by_kernel) or (swap_mode=="available" and not (killed_by_kernel or swapped_to_complete)):
                raise RuntimeError("R71_MEMORY_DIFFERENTIAL_NOT_PROVEN "+json.dumps(observed)+" stdout="+out.decode(errors="replace")[:200]+" stderr="+err.decode(errors="replace")[:350])
            observed["outcome"]="kernel_oom" if killed_by_kernel else "swap_backed_completion"
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
            if (group/"cgroup.procs").read_text().strip(): raise RuntimeError("R71_LEAKED_CGROUP_MEMBERS")
            group.rmdir()
def main():
    if len(sys.argv)==4 and sys.argv[1]=="worker":sys.exit(worker(Path(sys.argv[2]),sys.argv[3]))
    if len(sys.argv)!=2 or os.geteuid()!=0:raise RuntimeError("R71_DISPOSABLE_ROOT_ARGS_INVALID")
    if os.readlink("/proc/self/ns/net")==sys.argv[1]:raise RuntimeError("R71_NETNS_NOT_ISOLATED")
    if "memory" not in (ROOT/"cgroup.subtree_control").read_text().split():raise RuntimeError("R71_MEMORY_CONTROLLER_NOT_DELEGATED")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.settimeout(.2)
        code=sock.connect_ex(("192.0.2.1",443))
        if code not in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES):raise RuntimeError("R71_EGRESS_NOT_DENIED")
    results=[]
    for rep in range(3):
        for swap_mode in ("available","off"):
            for mode in ("control","mmap"):
                result=trial(mode,rep,swap_mode)
                results.append(result)
                print("R71_CASE_OK "+json.dumps(result,sort_keys=True),flush=True)
    print(json.dumps({"scope":"PUBLIC_SYNTHETIC_SAME_RUN_SWAP_DIFFERENTIAL","arch":os.uname().machine,"cases":results,
                      "private_source":False,"production_sandbox":False,"cpu_io_enforced":False,
                      "source_rights":"HOLD","release":"HOLD"},sort_keys=True),flush=True)
    print("R71_SAME_RUN_MEMCG_SWAP_DIFFERENTIAL_PASS arch=%s cases=12 product=NOT_RUN"%os.uname().machine,flush=True)
if __name__=="__main__":main()
