#!/usr/bin/env python3
"""E2-D19f: observe only the earned caller branch equality relation."""
from __future__ import annotations
import argparse, importlib.util, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time

_D19E=pathlib.Path(__file__).with_name("fritz_qemu_e2_d19e_read_branch_role.py")
_SPEC=importlib.util.spec_from_file_location("d19e",_D19E)
if _SPEC is None or _SPEC.loader is None: raise RuntimeError("unable to load D19e")
d19e=importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(d19e)
d19c=d19e.d19c; d17=d19e.d17; d13=d19e.d13; d14=d19e.d14
_D18=pathlib.Path(__file__).with_name("fritz_qemu_e2_d18_runtime_callsite_observe.py")
_S2=importlib.util.spec_from_file_location("d18",_D18)
if _S2 is None or _S2.loader is None: raise RuntimeError("unable to load D18")
d18=importlib.util.module_from_spec(_S2); _S2.loader.exec_module(d18); r6=d18.r6

SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-d19f-branch-relation/v1"
TARGET="_svctl_read"

def recover_peer_register(path:pathlib.Path,objdump:str)->dict:
    got=d13.readelf_selected_got(path)
    cp=subprocess.run([objdump,"-dr",str(path)],capture_output=True,text=True,timeout=60)
    if cp.returncode: raise RuntimeError("objdump failed")
    recs=d19c.instruction_records(cp.stdout)
    calls=[]
    for i,r in enumerate(recs):
        load=d13.got_load(r["asm"])
        if not load: continue
        reg,off=load
        if reg not in {"t9","25"} or got.get(off)!=TARGET: continue
        for j in range(i+1,len(recs)):
            asm=recs[j]["asm"]
            if d13.is_jalr_t9(asm): calls.append(j); break
            if d14.writes_t9(asm) or d14.control_transfer(asm): break
    if len(calls)!=1: raise RuntimeError("expected exactly one _svctl_read callsite")
    j=calls[0]
    for k in range(j+2,len(recs)):
        asm=recs[k]["asm"]
        if d19c.reads_v0(asm):
            m,ops=d14._parts(asm); regs=[d14._reg(x) for x in ops]
            if m not in {"beq","beql"} or "v0" not in regs[:2]:
                raise RuntimeError("earned predicate is not v0 equality branch")
            peer=regs[1] if regs[0]=="v0" else regs[0]
            if peer in {"zero","0","v0"}: raise RuntimeError("peer register is not a distinct register")
            return {"peer":peer,"peerClass":d17.reg_class(peer),"predicateClass":"v0_eq_register"}
        if d19c.writes_v0(asm) or d14.control_transfer(asm):
            break
    raise RuntimeError("unable to recover earned peer register")

def scalar_class(value:int)->str:
    value&=0xffffffff
    if value==0: return "zero"
    if value==1: return "one"
    if 2<=value<=16: return "small_positive"
    if value>=0xffff0000: return "negative_or_high_word"
    if value>=0x00010000: return "address_like"
    return "word_scalar"

def gdb_text(root:pathlib.Path,port:int,peer:str)->str:
    exe=root/r6.SVCTL.lstrip("/")
    solib=":".join(str(root/p) for p in ("lib","usr/lib"))
    return f"""set pagination off
set confirm off
set breakpoint pending on
set auto-solib-add on
set remotetimeout 2
set sysroot {root}
set solib-search-path {solib}
file {exe}
echo FRITZGDBSTAGE:pre_target\\n
target remote 127.0.0.1:{port}
echo FRITZGDBSTAGE:post_target\\n
python
import gdb, json

def scalar_class(value):
    value=int(value)&0xffffffff
    if value==0: return "zero"
    if value==1: return "one"
    if 2<=value<=16: return "small_positive"
    if value>=0xffff0000: return "negative_or_high_word"
    if value>=0x00010000: return "address_like"
    return "word_scalar"

class Ret(gdb.FinishBreakpoint):
    def __init__(self,frame):
        super().__init__(frame,internal=False); self.silent=True
    def stop(self):
        try:
            v0=int(gdb.parse_and_eval("$v0"))&0xffffffff
            peer=int(gdb.parse_and_eval("$"+{json.dumps(peer)}))&0xffffffff
            rec={{"v0Class":scalar_class(v0),"peerClass":scalar_class(peer),"equal":v0==peer}}
        except Exception:
            rec={{"v0Class":"unreadable","peerClass":"unreadable","equal":None}}
        print("FRITZREL:"+json.dumps(rec,sort_keys=True))
        self.enabled=False
        return True
class Entry(gdb.Breakpoint):
    def __init__(self):
        super().__init__("_svctl_read",internal=False); self.silent=True
    def stop(self):
        Ret(gdb.newest_frame()); self.enabled=False; return False
Entry()
end
echo FRITZGDBSTAGE:post_breakpoints\\n
continue
echo FRITZGDBSTAGE:post_continue_1\\n
detach
echo FRITZGDBSTAGE:post_detach\\n
quit
"""

def parse_obs(stdout:str)->list[dict]:
    out=[]
    for line in stdout.splitlines():
        if not line.startswith("FRITZREL:"): continue
        try:r=json.loads(line.split(":",1)[1])
        except json.JSONDecodeError:continue
        if set(r)=={"v0Class","peerClass","equal"}: out.append(r)
    return out

def instrumented_call(root:pathlib.Path,env:dict,verb:str,service:str,peer:str)->dict:
    try:
        gdb=shutil.which("gdb-multiarch")
        if not gdb: raise RuntimeError("gdb unavailable")
        exe=(root/r6.SVCTL.lstrip("/")).resolve()
        if d18.elf_type(exe)!="DYN": raise RuntimeError("requires ET_DYN svctl")
        port=d18._next_port()
        with tempfile.TemporaryDirectory(prefix="fritz-d19f-") as td:
            cmd=pathlib.Path(td)/"rel.gdb"; cmd.write_text(gdb_text(root,port,peer),encoding="utf-8")
            proc=subprocess.Popen(d18.instrumented_svctl_launch_argv(root,port,verb,service,host_strace=False),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env,start_new_session=True)
            ready=False; deadline=time.monotonic()+2.0
            while time.monotonic()<deadline:
                if d18.gdb_listener_seen(port): ready=True; break
                if proc.poll() is not None: break
                time.sleep(.05)
            gout="";gerr="";grc=None;timed=False
            if ready:
                try:
                    cp=subprocess.run([gdb,"--batch","--nx","-x",str(cmd)],capture_output=True,text=True,timeout=15)
                    grc=cp.returncode;gout=cp.stdout or "";gerr=cp.stderr or ""
                except subprocess.TimeoutExpired as exc:
                    timed=True;gout=exc.stdout or "";gerr=exc.stderr or ""
                    if isinstance(gout,bytes):gout=gout.decode("utf-8",errors="replace")
                    if isinstance(gerr,bytes):gerr=gerr.decode("utf-8",errors="replace")
            try:stdout,stderr=proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                stdout,stderr=proc.communicate(timeout=2)
        obs=parse_obs(gout); ok=bool(not timed and grc==0 and proc.returncode is not None and len(obs)==1)
        return {"verb":verb,"service":service,"exitCode":proc.returncode,"stdoutBytes":len(stdout.encode()),"stderrBytes":len(stderr.encode()),
            "instrumentation":{"ready":ok,"observations":obs,"observationCount":len(obs),"hostStraceUsed":False,
              "gdbListenerSeen":ready,"gdbAttempted":ready,"gdbStages":d18.parse_gdb_stages(gout),
              "rawDebuggerOutputPublished":False,"rawRegisterValuesPublished":False,
              "peerRegisterNamePublished":False,"numericValuesPublished":False},"rawOutputPublished":False}
    except Exception as exc:
        return {"verb":verb,"service":service,"exitCode":None,"stdoutBytes":0,"stderrBytes":0,
          "instrumentation":{"ready":False,"reason":"instrumentation_exception","errorType":type(exc).__name__,
          "observations":[],"observationCount":0,"hostStraceUsed":False,"rawDebuggerOutputPublished":False,
          "rawRegisterValuesPublished":False,"peerRegisterNamePublished":False,"numericValuesPublished":False},"rawOutputPublished":False}

_ACTIVE_PEER=None
def safe_call(root,env,verb,service): return instrumented_call(root,env,verb,service,_ACTIVE_PEER)
def ns_helper(args):
    old=r6.svctl_call;r6.svctl_call=safe_call
    try:return r6.namespace_helper(args)
    finally:r6.svctl_call=old

def summarize(runtime):
    per={}
    for key in ("preStatus","start","postStatus"):
        i=(runtime.get(key) or {}).get("instrumentation") or {};obs=i.get("observations") or []
        o=obs[0] if len(obs)==1 else {}
        per[key]={"ready":i.get("ready") is True,"hitCount":len(obs),"v0Class":o.get("v0Class"),
          "peerClass":o.get("peerClass"),"equal":o.get("equal"),"hostStraceUsed":i.get("hostStraceUsed"),"gdbStages":i.get("gdbStages") or []}
    ready=all(v["ready"] for v in per.values())
    stable=ready and per["preStatus"]["equal"]==per["postStatus"]["equal"] and per["preStatus"]["v0Class"]==per["postStatus"]["v0Class"] and per["preStatus"]["peerClass"]==per["postStatus"]["peerClass"]
    differs=stable and (per["start"]["equal"],per["start"]["v0Class"],per["start"]["peerClass"])!=(per["preStatus"]["equal"],per["preStatus"]["v0Class"],per["preStatus"]["peerClass"])
    return {"allCallsInstrumentationReady":ready,"allExpectedHits":ready and all(v["hitCount"]==1 for v in per.values()),
      "prePostStatusStable":stable,"startDiffersFromStableStatus":differs,"perCall":per,
      "rawValuesPublished":False,"peerRegisterNamePublished":False}

def classify(s):
    if not s["allCallsInstrumentationReady"] or not s["allExpectedHits"]: return "E2_D19F_BRANCH_RELATION_INSTRUMENTATION_INCOMPLETE"
    if not s["prePostStatusStable"]: return "E2_D19F_BRANCH_RELATION_STATUS_UNSTABLE"
    if s["startDiffersFromStableStatus"]: return "E2_D19F_BRANCH_RELATION_DISCRIMINATOR_FOUND"
    return "E2_D19F_BRANCH_RELATION_NO_DISCRIMINATOR"

def run_probe(args):
    global _ACTIVE_PEER
    root,meta=r6.prepare_root(args)
    peer_info=recover_peer_register((root/r6.SVCTL.lstrip("/")).resolve(),shutil.which("mips-linux-gnu-objdump") or "mips-linux-gnu-objdump")
    _ACTIVE_PEER=peer_info["peer"]
    ns=pathlib.Path(args.work_dir).resolve()/"namespace-result-d19f.json"
    cp=r6._run(["sudo","-n","unshare","--net","--pid","--fork","--kill-child","--mount-proc",sys.executable,
      str(pathlib.Path(__file__).resolve()),"--namespace-helper","--root",str(root),"--namespace-result",str(ns),
      "--control-wait-seconds",str(args.control_wait_seconds),"--verify-seconds",str(args.verify_seconds),
      "--sample-interval-seconds",str(args.sample_interval_seconds),"--peer-register",_ACTIVE_PEER],
      timeout=max(60,int(args.control_wait_seconds+args.verify_seconds)+45))
    if cp.returncode!=0 or not ns.exists(): raise RuntimeError("isolated D19f probe failed")
    runtime=json.loads(ns.read_text(encoding="utf-8"));s=summarize(runtime);c=classify(s)
    return {"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":c,
      "oracleSatisfied":bool(runtime.get("probeCompleted") and s["allCallsInstrumentationReady"] and s["allExpectedHits"]),**meta,
      "transaction":{"inspect":["svctl","status","ctlmgr"],"apply":["svctl","start","ctlmgr"],
        "applyCount":1 if runtime.get("start",{}).get("exitCode") is not None else 0,"verify":["svctl","status","ctlmgr"],"disposalIsRollback":True},
      "staticPrecondition":{"predicateClass":"v0_eq_register","peerRegisterClass":peer_info["peerClass"],
        "peerRegisterNamePublished":False,"branchOutcomeAccepted":False},
      "instrumentation":s,
      "runtimeSummary":{"statusChanged":runtime.get("statusChanged"),"ctlmgrProcessObserved":runtime.get("ctlmgrProcessObserved"),
        "maxCtlmgrProcessCount":runtime.get("maxCtlmgrProcessCount")},
      "interpretationBoundary":{"observedRelation":"v0_equals_exact_peer_register","rawRegisterValuesPublished":False,
        "peerRegisterNamePublished":False,"numericValuesPublished":False,"branchOutcomePublished":False,
        "responsePayloadPublished":False,"responseFieldLayoutAccepted":False,"protocolEnumValuesAccepted":False,
        "payloadOffsetsAccepted":False,"libcReadOwnershipInferred":False,"sameRunWireCaptureExcluded":True,
        "hostStraceExcluded":True,"physicalRouterContact":False,"modifiedHilAuthorized":False},
      "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"rawDebuggerOutputPublished":False,
        "rawRegisterValuesPublished":False,"peerRegisterNamePublished":False,"wirePayloadPublished":False,
        "physicalRouterContact":False,"routerMutationAuthorized":False,"externalNetworkAvailableToTarget":False,
        "shippedFilesModified":False,"disposableEmulatorMutationOnly":True}}

def parse_args(argv=None):
    p=argparse.ArgumentParser();p.add_argument("--firmware-url");p.add_argument("--expected-size",type=int);p.add_argument("--expected-sha256")
    p.add_argument("--work-dir");p.add_argument("--receipt");p.add_argument("--control-wait-seconds",type=float,default=2.0)
    p.add_argument("--verify-seconds",type=float,default=2.0);p.add_argument("--sample-interval-seconds",type=float,default=.05)
    p.add_argument("--namespace-helper",action="store_true");p.add_argument("--root");p.add_argument("--namespace-result");p.add_argument("--peer-register");return p.parse_args(argv)
def main(argv=None):
    global _ACTIVE_PEER
    args=parse_args(argv)
    if args.namespace_helper:
        if not args.root or not args.namespace_result or not args.peer_register: raise SystemExit("helper requires root/result/peer")
        _ACTIVE_PEER=args.peer_register;return ns_helper(args)
    if any(v is None for v in (args.firmware_url,args.expected_size,args.expected_sha256,args.work_dir,args.receipt)):raise SystemExit("normal mode requires firmware/size/hash/work/receipt")
    rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
    try:data=run_probe(args);rc=0 if data.get("oracleSatisfied") else 2
    except Exception as exc:data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,"error":{"type":type(exc).__name__,"message":str(exc)[:1000]}};rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8");print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True));return rc
if __name__=="__main__":raise SystemExit(main())
