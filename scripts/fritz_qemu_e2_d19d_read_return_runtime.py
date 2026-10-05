#!/usr/bin/env python3
"""E2-D19d: debugger-only _svctl_read return scalar-class observation."""
from __future__ import annotations
import argparse, importlib.util, json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time

_D18=pathlib.Path(__file__).with_name("fritz_qemu_e2_d18_runtime_callsite_observe.py")
_SPEC=importlib.util.spec_from_file_location("d18",_D18)
if _SPEC is None or _SPEC.loader is None: raise RuntimeError("unable to load D18")
d18=importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(d18)
r6=d18.r6
SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-d19d-svctl-read-return/v1"
ROLE_DOC=pathlib.Path(__file__).resolve().parents[1]/"evidence"/"fritz-e2-d19-response-role.json"

def role_precondition()->dict:
    r=json.loads(ROLE_DOC.read_text(encoding="utf-8"))
    if r.get("classification")!="E2_D19_SVCTL_READ_ENTRY_ROLE_EARNED" or r.get("oracleSatisfied") is not True:
        raise RuntimeError("D19 entry role not accepted")
    return r

def gdb_text(root:pathlib.Path,port:int)->str:
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
        super().__init__(frame,internal=False)
        self.silent=True
    def stop(self):
        try:
            cls=scalar_class(gdb.parse_and_eval("$v0"))
        except Exception:
            cls="unreadable"
        print("FRITZRET:"+json.dumps({{"scalarClass":cls}},sort_keys=True))
        self.enabled=False
        return True

class Entry(gdb.Breakpoint):
    def __init__(self):
        super().__init__("_svctl_read",internal=False)
        self.silent=True
    def stop(self):
        Ret(gdb.newest_frame())
        self.enabled=False
        return False

Entry()
end
echo FRITZGDBSTAGE:post_breakpoints\\n
continue
echo FRITZGDBSTAGE:post_continue_1\\n
detach
echo FRITZGDBSTAGE:post_detach\\n
quit
"""

def parse_return(stdout:str)->list[dict]:
    out=[]
    for line in stdout.splitlines():
        if not line.startswith("FRITZRET:"): continue
        try: v=json.loads(line.split(":",1)[1])
        except json.JSONDecodeError: continue
        if set(v)=={"scalarClass"} and isinstance(v["scalarClass"],str): out.append(v)
    return out

def instrumented_call(root:pathlib.Path,env:dict,verb:str,service:str)->dict:
    stage="tool_discovery"
    try:
        gdb=shutil.which("gdb-multiarch")
        if not gdb: raise RuntimeError("gdb-multiarch unavailable")
        exe=(root/r6.SVCTL.lstrip("/")).resolve()
        if d18.elf_type(exe)!="DYN": raise RuntimeError("return observation requires ET_DYN svctl")
        port=d18._next_port()
        with tempfile.TemporaryDirectory(prefix="fritz-d19d-") as td:
            cmd=pathlib.Path(td)/"return.gdb"; cmd.write_text(gdb_text(root,port),encoding="utf-8")
            proc=subprocess.Popen(
                d18.instrumented_svctl_launch_argv(root,port,verb,service,host_strace=False),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env,start_new_session=True)
            ready=False; deadline=time.monotonic()+2.0
            while time.monotonic()<deadline:
                if d18.gdb_listener_seen(port): ready=True; break
                if proc.poll() is not None: break
                time.sleep(.05)
            attempted=ready; timed=False; grc=None; gout=""; gerr=""
            if ready:
                try:
                    cp=subprocess.run([gdb,"--batch","--nx","-x",str(cmd)],capture_output=True,text=True,timeout=15)
                    grc=cp.returncode; gout=cp.stdout or ""; gerr=cp.stderr or ""
                except subprocess.TimeoutExpired as exc:
                    timed=True; gout=exc.stdout or ""; gerr=exc.stderr or ""
                    if isinstance(gout,bytes): gout=gout.decode("utf-8",errors="replace")
                    if isinstance(gerr,bytes): gerr=gerr.decode("utf-8",errors="replace")
            try: stdout,stderr=proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try: os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                stdout,stderr=proc.communicate(timeout=2)
        obs=parse_return(gout)
        complete=bool(not timed and grc==0 and proc.returncode is not None and len(obs)==1)
        return {
          "verb":verb,"service":service,"exitCode":proc.returncode,
          "stdoutBytes":len(stdout.encode("utf-8",errors="replace")),
          "stderrBytes":len(stderr.encode("utf-8",errors="replace")),
          "stateMarkers":r6.state_markers(stdout,set()),
          "instrumentation":{
            "ready":complete,"reason":"ok" if complete else "debugger_incomplete",
            "bindingMode":"finish_breakpoint_from_symbol_entry","hostStraceUsed":False,
            "observations":obs,"observationCount":len(obs),
            "gdbListenerSeen":ready,"gdbAttempted":attempted,
            "gdbConnectionSeen":"post_target" in d18.parse_gdb_stages(gout),
            "gdbStages":d18.parse_gdb_stages(gout),
            "gdbExitClass":"timeout" if timed else "zero" if grc==0 else "nonzero",
            "rawDebuggerOutputPublished":False,"rawRegisterValuesPublished":False,
            "returnValuePublished":False,"callsiteAddressesPublished":False
          },"rawOutputPublished":False}
    except Exception as exc:
        return {"verb":verb,"service":service,"exitCode":None,"stdoutBytes":0,"stderrBytes":0,"stateMarkers":[],
          "instrumentation":{"ready":False,"reason":"instrumentation_exception","errorType":type(exc).__name__,
            "errorStage":stage,"observations":[],"observationCount":0,"hostStraceUsed":False,
            "rawDebuggerOutputPublished":False,"rawRegisterValuesPublished":False,
            "returnValuePublished":False,"callsiteAddressesPublished":False},"rawOutputPublished":False}

def safe_call(root,env,verb,service): return instrumented_call(root,env,verb,service)

def ns_helper(args):
    old=r6.svctl_call; r6.svctl_call=safe_call
    try: return r6.namespace_helper(args)
    finally: r6.svctl_call=old

def summarize(runtime:dict)->dict:
    vals={}
    for key in ("preStatus","start","postStatus"):
        call=runtime.get(key) or {}; i=call.get("instrumentation") or {}; obs=i.get("observations") or []
        vals[key]={"ready":i.get("ready") is True,"scalarClass":obs[0]["scalarClass"] if len(obs)==1 else None,
                   "hitCount":len(obs),"gdbStages":i.get("gdbStages") or [],"hostStraceUsed":i.get("hostStraceUsed")}
    all_ready=all(v["ready"] for v in vals.values())
    status_stable=all_ready and vals["preStatus"]["scalarClass"]==vals["postStatus"]["scalarClass"]
    start_differs=status_stable and vals["start"]["scalarClass"]!=vals["preStatus"]["scalarClass"]
    return {"allCallsInstrumentationReady":all_ready,"allExpectedReturnHits":all_ready and all(v["hitCount"]==1 for v in vals.values()),
      "prePostStatusStable":status_stable,"startDiffersFromStableStatus":start_differs,
      "perCall":vals,"returnValuePublished":False}

def classify(s:dict)->str:
    if not s["allCallsInstrumentationReady"] or not s["allExpectedReturnHits"]:
        return "E2_D19D_SVCTL_READ_RETURN_INSTRUMENTATION_INCOMPLETE"
    if not s["prePostStatusStable"]:
        return "E2_D19D_SVCTL_READ_RETURN_STATUS_UNSTABLE"
    if s["startDiffersFromStableStatus"]:
        return "E2_D19D_SVCTL_READ_RETURN_CLASS_DISCRIMINATOR_FOUND"
    return "E2_D19D_SVCTL_READ_RETURN_CLASS_NO_DISCRIMINATOR"

def run_probe(args):
    role_precondition()
    root,meta=r6.prepare_root(args)
    ns=pathlib.Path(args.work_dir).resolve()/"namespace-result-d19d.json"
    cp=r6._run(["sudo","-n","unshare","--net","--pid","--fork","--kill-child","--mount-proc",
      sys.executable,str(pathlib.Path(__file__).resolve()),"--namespace-helper","--root",str(root),
      "--namespace-result",str(ns),"--control-wait-seconds",str(args.control_wait_seconds),
      "--verify-seconds",str(args.verify_seconds),"--sample-interval-seconds",str(args.sample_interval_seconds)],
      timeout=max(60,int(args.control_wait_seconds+args.verify_seconds)+45))
    if cp.returncode!=0 or not ns.exists(): raise RuntimeError("isolated D19d probe failed")
    runtime=json.loads(ns.read_text(encoding="utf-8")); s=summarize(runtime); c=classify(s)
    oracle=bool(runtime.get("probeCompleted") and s["allCallsInstrumentationReady"] and s["allExpectedReturnHits"])
    return {"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":c,"oracleSatisfied":oracle,**meta,
      "transaction":{"inspect":["svctl","status","ctlmgr"],"apply":["svctl","start","ctlmgr"],
        "applyCount":1 if runtime.get("start",{}).get("exitCode") is not None else 0,
        "verify":["svctl","status","ctlmgr"],"disposalIsRollback":True},
      "staticPrecondition":{"d19cReturnUseRoleEarned":True,"returnUseClass":"branch_condition",
        "postCallInstructionCountToFirstUse":1,"returnValuePublished":False},
      "instrumentation":s,
      "runtimeSummary":{"statusChanged":runtime.get("statusChanged"),"ctlmgrProcessObserved":runtime.get("ctlmgrProcessObserved"),
        "maxCtlmgrProcessCount":runtime.get("maxCtlmgrProcessCount")},
      "interpretationBoundary":{"observedRole":"_svctl_read_return_scalar_class","finishBreakpointOnly":True,
        "numericReturnValuePublished":False,"branchOutcomePublished":False,"libcReadOwnershipInferred":False,
        "responsePayloadPublished":False,"responseFieldLayoutAccepted":False,"protocolEnumValuesAccepted":False,
        "payloadOffsetsAccepted":False,"hostStraceExcluded":True,"sameRunWireCaptureExcluded":True,
        "physicalRouterContact":False,"modifiedHilAuthorized":False},
      "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"rawDebuggerOutputPublished":False,
        "rawRegisterValuesPublished":False,"returnValuePublished":False,"callsiteAddressesPublished":False,
        "wirePayloadPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False,
        "externalNetworkAvailableToTarget":False,"shippedFilesModified":False,"disposableEmulatorMutationOnly":True}}

def parse_args(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--firmware-url"); p.add_argument("--expected-size",type=int); p.add_argument("--expected-sha256")
    p.add_argument("--work-dir"); p.add_argument("--receipt"); p.add_argument("--control-wait-seconds",type=float,default=2.0)
    p.add_argument("--verify-seconds",type=float,default=2.0); p.add_argument("--sample-interval-seconds",type=float,default=.05)
    p.add_argument("--namespace-helper",action="store_true"); p.add_argument("--root"); p.add_argument("--namespace-result"); return p.parse_args(argv)

def main(argv=None):
    args=parse_args(argv)
    if args.namespace_helper:
        if not args.root or not args.namespace_result: raise SystemExit("namespace helper requires root/result")
        return ns_helper(args)
    if any(v is None for v in (args.firmware_url,args.expected_size,args.expected_sha256,args.work_dir,args.receipt)):
        raise SystemExit("normal mode requires firmware/size/hash/work/receipt")
    rp=pathlib.Path(args.receipt); rp.parent.mkdir(parents=True,exist_ok=True)
    try: data=run_probe(args); rc=0 if data.get("oracleSatisfied") else 2
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
          "error":{"type":type(exc).__name__,"message":str(exc)[:1000]}}; rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True)); return rc
if __name__=="__main__": raise SystemExit(main())
