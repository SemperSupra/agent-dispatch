#!/usr/bin/env python3
"""E2-D19e: classify the earned caller branch after _svctl_read."""
from __future__ import annotations
import argparse, importlib.util, json, pathlib, re, shutil, subprocess

_D19C=pathlib.Path(__file__).with_name("fritz_qemu_e2_d19c_read_return_role.py")
_SPEC=importlib.util.spec_from_file_location("d19c",_D19C)
if _SPEC is None or _SPEC.loader is None: raise RuntimeError("unable to load D19c")
d19c=importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(d19c)
d17=d19c.d17; d13=d19c.d13; d14=d19c.d14; base=d19c.base
SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-d19e-read-branch-role/v1"
SVCTL="/bin/svctl"; TARGET="_svctl_read"

def predicate_class(asm:str)->str:
    m,ops=d14._parts(asm); regs=[d14._reg(x) for x in ops]
    if not (m.startswith("b") and m!="break"): return "not_branch"
    if m in {"beq","beql"} and len(regs)>=2:
        pair=set(regs[:2])
        if "v0" in pair and ("zero" in pair or "0" in pair): return "v0_eq_zero"
        if "v0" in pair: return "v0_eq_register"
    if m in {"bne","bnel"} and len(regs)>=2:
        pair=set(regs[:2])
        if "v0" in pair and ("zero" in pair or "0" in pair): return "v0_ne_zero"
        if "v0" in pair: return "v0_ne_register"
    if m in {"bgez","bgezl","bgtz","bgtzl","blez","blezl","bltz","bltzl"} and regs and regs[0]=="v0":
        return {"bgez":"v0_ge_zero","bgezl":"v0_ge_zero","bgtz":"v0_gt_zero","bgtzl":"v0_gt_zero",
                "blez":"v0_le_zero","blezl":"v0_le_zero","bltz":"v0_lt_zero","bltzl":"v0_lt_zero"}[m]
    return "other_v0_branch" if "v0" in regs else "branch_not_on_v0"

def instruction_class(asm:str)->str:
    m,_=d14._parts(asm)
    if m in {"jal","jalr","bal"}: return "call"
    if m=="jr": return "return_or_indirect_jump"
    if m in {"j","b"} or (m.startswith("b") and m!="break"): return "branch"
    if d19c.writes_v0(asm): return "v0_write"
    if d19c.reads_v0(asm): return "v0_read"
    return "other"

def branch_target(asm:str)->int|None:
    _,ops=d14._parts(asm)
    if not ops: return None
    token=ops[-1].strip().split()[0]
    token=token.rstrip(",")
    try: return int(token,16 if re.fullmatch(r"[0-9a-fA-F]+",token) else 0)
    except ValueError: return None

def recover(path:pathlib.Path,objdump:str,got:dict[int,str])->dict:
    cp=subprocess.run([objdump,"-dr",str(path)],capture_output=True,text=True,timeout=60)
    if cp.returncode: raise RuntimeError("objdump failed")
    recs=d19c.instruction_records(cp.stdout); by_addr={r["addr"]:i for i,r in enumerate(recs)}
    call_indices=[]
    for i,r in enumerate(recs):
        load=d13.got_load(r["asm"])
        if not load: continue
        reg,off=load
        if reg not in {"t9","25"} or got.get(off)!=TARGET: continue
        for j in range(i+1,len(recs)):
            asm=recs[j]["asm"]
            if d13.is_jalr_t9(asm): call_indices.append(j); break
            if d14.writes_t9(asm) or d14.control_transfer(asm): break
    if len(call_indices)!=1:
        return {"acceptedCallsiteCount":len(call_indices),"branchRoleEarned":False,"reason":"callsite_count_not_one"}
    j=call_indices[0]
    for k in range(j+2,len(recs)):
        asm=recs[k]["asm"]
        if d19c.reads_v0(asm):
            pc=predicate_class(asm)
            if pc=="not_branch":
                return {"acceptedCallsiteCount":1,"branchRoleEarned":False,"reason":"first_v0_use_not_branch"}
            delay=recs[k+1]["asm"] if k+1<len(recs) else ""
            fall=recs[k+2]["asm"] if k+2<len(recs) else ""
            tgt=branch_target(asm); taken=None
            if tgt is not None and tgt in by_addr: taken=recs[by_addr[tgt]]["asm"]
            return {
              "acceptedCallsiteCount":1,"branchRoleEarned":True,"predicateClass":pc,
              "delaySlotClass":instruction_class(delay) if delay else "missing",
              "fallthroughSuccessorClass":instruction_class(fall) if fall else "missing",
              "takenSuccessorResolved":taken is not None,
              "takenSuccessorClass":instruction_class(taken) if taken else None,
              "firstV0UseDistanceAfterCall":k-j-1,
              "reason":"bounded_branch_role"}
        if d19c.writes_v0(asm) or d14.control_transfer(asm):
            return {"acceptedCallsiteCount":1,"branchRoleEarned":False,"reason":"boundary_before_v0_branch"}
    return {"acceptedCallsiteCount":1,"branchRoleEarned":False,"reason":"function_end"}

def classify(r):
    if r.get("branchRoleEarned"): return "E2_D19E_SVCTL_READ_CALLER_BRANCH_ROLE_EARNED"
    if r.get("acceptedCallsiteCount")==1: return "E2_D19E_SVCTL_READ_CALLER_BRANCH_PARTIAL"
    return "E2_D19E_SVCTL_READ_CALLSITE_NOT_UNIQUE"

def run_probe(args):
    work=pathlib.Path(args.work_dir).resolve(); fw=work/"firmware.image"; payload=work/"payload"; roots=work/"roots"; scratch=work/"scratch"
    for p in (fw.parent,payload,roots,scratch): p.mkdir(parents=True,exist_ok=True)
    exact=base.download_exact(args.firmware_url,fw,expected_size=args.expected_size,expected_sha256=args.expected_sha256)
    base.extract_outer(fw,payload); root=base.select_root(base.extract_squashfs_roots(payload,roots,scratch))
    svctl=(root/SVCTL.lstrip("/")).resolve(); objdump=shutil.which(args.objdump)
    if not objdump: raise RuntimeError("objdump unavailable")
    r=recover(svctl,objdump,d13.readelf_selected_got(svctl))
    return {"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":classify(r),"oracleSatisfied":True,
      "target":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),"observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
      "branchRole":r,
      "interpretationBoundary":{"predicateClassOnly":True,"successorClassesOnly":True,"branchAddressPublished":False,
        "branchTargetAddressPublished":False,"rawDisassemblyPublished":False,"numericReturnValuePublished":False,
        "branchOutcomeAccepted":False,"libcReadOwnershipInferred":False,"responsePayloadPublished":False,
        "responseFieldLayoutAccepted":False,"protocolEnumValuesAccepted":False,"payloadOffsetsAccepted":False,
        "physicalRouterContact":False,"modifiedHilAuthorized":False},
      "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"binaryPayloadPublished":False,
        "rawDisassemblyPublished":False,"instructionAddressesPublished":False,"gotOffsetsPublished":False,
        "wirePayloadPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False}}

def parse_args(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--firmware-url",required=True); p.add_argument("--expected-size",type=int,required=True)
    p.add_argument("--expected-sha256",required=True); p.add_argument("--objdump",default="mips-linux-gnu-objdump")
    p.add_argument("--work-dir",required=True); p.add_argument("--receipt",required=True); return p.parse_args(argv)
def main(argv=None):
    args=parse_args(argv); rp=pathlib.Path(args.receipt); rp.parent.mkdir(parents=True,exist_ok=True)
    try: data=run_probe(args); rc=0
    except Exception as exc: data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,"error":{"type":type(exc).__name__,"message":str(exc)[:1000]}}; rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True)); return rc
if __name__=="__main__": raise SystemExit(main())
