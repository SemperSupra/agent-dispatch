#!/usr/bin/env python3
"""R69 public-only RLIMIT_AS capability and aggregate-memory limitation."""
import errno,json,mmap,os,resource,socket,subprocess,sys,time
from pathlib import Path
MB=1048576
LIMIT=112*MB
def anon(size):
    with mmap.mmap(-1,size,access=mmap.ACCESS_WRITE) as m:
        for i in range(0,size,4096):
            m[i]=13
        return True
def rss(pid):
    for line in (Path("/proc")/str(pid)/"status").read_text().splitlines():
        if line.startswith("VmRSS:"):return int(line.split()[1])*1024
    return 0
def child(mode,stage):
    resource.setrlimit(resource.RLIMIT_AS,(LIMIT,LIMIT))
    if resource.getrlimit(resource.RLIMIT_AS)!=(LIMIT,LIMIT):
        raise RuntimeError("R69_LIMIT_NOT_SET")
    if mode=="control":
        anon(16*MB)
        print("R69_CONTROL_OK",flush=True)
        return
    if mode=="denial":
        try:
            anon(256*MB)
        except (MemoryError,OSError) as e:
            if isinstance(e,OSError) and e.errno!=errno.ENOMEM:raise
            print("R69_SINGLE_PROCESS_ENOMEM",flush=True)
            return
        raise RuntimeError("R69_OVERSIZE_ALLOCATION_ALLOWED")
    if mode=="hold":
        anon_map=mmap.mmap(-1,72*MB,access=mmap.ACCESS_WRITE)
        for i in range(0,72*MB,4096):
            anon_map[i]=17
        (stage/("ready-"+str(os.getpid()))).write_text("72M")
        deadline=time.monotonic()+5
        while not (stage/"release").exists():
            if time.monotonic()>deadline:raise RuntimeError("R69_HOLD_TIMEOUT")
            time.sleep(.015)
        anon_map.close()
        return
    raise RuntimeError("R69_UNKNOWN_MODE")
def run(args,timeout=4):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     timeout=timeout,check=False)
    return p.returncode,p.stdout,p.stderr
def trial(stage,rep):
    root=stage/("rep-"+str(rep))
    root.mkdir()
    childcmd=lambda mode:[sys.executable,"-B",__file__,"child",mode,str(root)]
    normal=run(childcmd("control"))
    if normal[0]!=0 or b"R69_CONTROL_OK" not in normal[1]:
        raise RuntimeError("R69_CONTROL_FAILED "+normal[2].decode(errors="replace")[:160])
    denied=run(childcmd("denial"))
    if denied[0]!=0 or b"R69_SINGLE_PROCESS_ENOMEM" not in denied[1]:
        raise RuntimeError("R69_SINGLE_PROCESS_DENIAL_FAILED "+denied[2].decode(errors="replace")[:160])
    pair=[subprocess.Popen(childcmd("hold"),stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True) for _ in range(2)]
    seen=[]
    try:
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if all((root/("ready-"+str(p.pid))).exists() for p in pair):break
            if any(p.poll() is not None for p in pair):raise RuntimeError("R69_HOLDER_EARLY_EXIT")
            time.sleep(.015)
        if not all((root/("ready-"+str(p.pid))).exists() for p in pair):
            raise RuntimeError("R69_AGGREGATE_READY_TIMEOUT")
        seen=[rss(p.pid) for p in pair]
        if min(seen)<64*MB or sum(seen)<=LIMIT:
            raise RuntimeError("R69_AGGREGATE_RSS_NOT_OVER_PER_PROCESS_LIMIT:"+str(seen))
        (root/"release").touch()
        for p in pair:
            out,err=p.communicate(timeout=3)
            if p.returncode!=0:raise RuntimeError("R69_HOLDER_FAILED "+err.decode(errors="replace")[:140])
        return {"rep":rep,"limit_bytes_per_process":LIMIT,"single_process_denied":True,
                "two_concurrent_rss_bytes":seen,
                "aggregate_rss_exceeds_one_process_limit":True,
                "admission":"RLIMIT_AS_SINGLE_PROCESS_ONLY"}
    finally:
        for p in pair:
            if p.poll() is None:p.kill()
            p.communicate(timeout=3)
        for p in root.iterdir():
            if not p.is_file() or p.is_symlink():raise RuntimeError("R69_UNSAFE_CLEANUP")
            p.unlink()
        root.rmdir()
def main():
    if len(sys.argv)==4 and sys.argv[1]=="child":
        child(sys.argv[2],Path(sys.argv[3]))
        return
    if len(sys.argv)!=3:raise RuntimeError("R69_ARGS_INVALID")
    if os.readlink("/proc/self/ns/net")==sys.argv[1]:raise RuntimeError("R69_NETNS_UNSEPARATED")
    if (os.geteuid(),os.getegid())!=(65534,65534):raise RuntimeError("R69_ROOT_NOT_DROPPED")
    cap=[l.split()[1] for l in Path("/proc/self/status").read_text().splitlines() if l.startswith("CapEff:")]
    if len(cap)!=1 or int(cap[0],16)!=0:raise RuntimeError("R69_CAPS_NOT_ZERO")
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(.2)
        e=s.connect_ex(("192.0.2.1",443))
        if e not in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EPERM,errno.EACCES):raise RuntimeError("R69_EGRESS_ROUTE_EXISTS")
    stage=Path(sys.argv[2]).resolve()
    rows=[trial(stage,i) for i in range(3)]
    if len(rows)!=3 or list(stage.iterdir()):raise RuntimeError("R69_REPS_OR_CLEANUP_FAILED")
    print(json.dumps({"scope":"PUBLIC_SYNTHETIC_RLIMIT_AS_ONLY","arch":os.uname().machine,
                      "reps":3,"rows":rows,"product_enforced":False,"whole_tree_memory_bound":False,
                      "private_source":False,"release":"HOLD"},sort_keys=True),flush=True)
    print("R69_RLIMIT_AS_LOCAL_AND_AGGREGATE_ESCAPE_PASS arch=%s reps=3 product=NOT_RUN"%os.uname().machine,flush=True)
if __name__=="__main__":main()
