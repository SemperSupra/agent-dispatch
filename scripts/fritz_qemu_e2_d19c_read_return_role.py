#!/usr/bin/env python3
"""E2-D19c: bounded caller-side _svctl_read return-use role recovery."""
from __future__ import annotations
import argparse, importlib.util, json, pathlib, shutil, subprocess

_D17=pathlib.Path(__file__).with_name("fritz_qemu_e2_d17_svctl_callsite_args.py")
_SPEC=importlib.util.spec_from_file_location("d17",_D17)
if _SPEC is None or _SPEC.loader is None: raise RuntimeError("unable to load D17")
d17=importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(d17)
d13=d17.d13; d14=d17.d14; base=d17.base

SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-d19c-svctl-read-return-role/v1"
TARGET="_svctl_read"
SVCTL="/bin/svctl"

def instruction_records(text:str)->list[dict]:
    out=[]
    import re
    rx=re.compile(r"^\s*(?P<addr>[0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2,8}\s+)+(?P<asm>.+)$")
    for line in text.splitlines():
        m=rx.match(line)
        if m: out.append({"addr":int(m.group("addr"),16),"asm":m.group("asm").strip()})
    return out

def reads_v0(asm:str)->bool:
    mnemonic,ops=d14._parts(asm)
    if not ops: return False
    regs=[d14._reg(x) for x in ops]
    if mnemonic in {"move","addu","add","subu","sub","or","and","xor","slt","sltu","addiu","addi"}:
        return "v0" in regs[1:]
    if mnemonic.startswith("b") and mnemonic!="break":
        return "v0" in regs
    if mnemonic in {"sw","sd","sb","sh"}:
        return bool(regs and regs[0]=="v0")
    return "v0" in regs[1:]

def writes_v0(asm:str)->bool:
    mnemonic,ops=d14._parts(asm)
    if not ops: return False
    if mnemonic in {"sw","sd","sb","sh","beq","bne","beql","bnel","j","jr","jal","jalr","bal","syscall","break","nop"}:
        return False
    return d14._reg(ops[0])=="v0"

def use_class(asm:str)->str:
    mnemonic,ops=d14._parts(asm)
    regs=[d14._reg(x) for x in ops]
    if mnemonic.startswith("b") and mnemonic!="break": return "branch_condition"
    if mnemonic=="move" and len(regs)>=2 and regs[1]=="v0":
        return "argument_transfer" if regs[0] in {"a0","a1","a2","a3"} else "register_move"
    if mnemonic in {"sw","sd","sb","sh"} and regs and regs[0]=="v0": return "store"
    if len(regs)>=2 and "v0" in regs[1:]: return "alu_or_address_use"
    return "other_read"

def recover_return_use(path:pathlib.Path,objdump:str,got:dict[int,str])->dict:
    cp=subprocess.run([objdump,"-dr",str(path)],capture_output=True,text=True,timeout=60)
    if cp.returncode: raise RuntimeError("objdump failed for /bin/svctl")
    recs=instruction_records(cp.stdout)
    calls=[]
    for i,rec in enumerate(recs):
        load=d13.got_load(rec["asm"])
        if not load: continue
        reg,off=load
        if reg not in {"t9","25"} or got.get(off)!=TARGET: continue
        for j in range(i+1,len(recs)):
            asm=recs[j]["asm"]
            if d13.is_jalr_t9(asm):
                calls.append(j); break
            if d14.writes_t9(asm) or d14.control_transfer(asm): break
    if len(calls)!=1:
        return {"acceptedCallsiteCount":len(calls),"roleEarned":False,"reason":"callsite_count_not_one"}
    j=calls[0]
    delay=recs[j+1]["asm"] if j+1<len(recs) else ""
    delay_reads=reads_v0(delay) if delay else False
    delay_writes=writes_v0(delay) if delay else False
    scanned=0
    for k in range(j+2,len(recs)):
        asm=recs[k]["asm"]; scanned+=1
        if reads_v0(asm):
            return {"acceptedCallsiteCount":1,"delaySlotReadsV0":delay_reads,"delaySlotWritesV0":delay_writes,
                    "postCallInstructionCountToFirstUse":scanned,"firstReturnUseClass":use_class(asm),
                    "returnValueClobberedBeforeUse":False,"roleEarned":True,"reason":"bounded_first_v0_use"}
        if writes_v0(asm):
            return {"acceptedCallsiteCount":1,"delaySlotReadsV0":delay_reads,"delaySlotWritesV0":delay_writes,
                    "postCallInstructionCountToFirstUse":scanned,"firstReturnUseClass":None,
                    "returnValueClobberedBeforeUse":True,"roleEarned":False,"reason":"v0_clobbered_before_use"}
        if d14.control_transfer(asm):
            return {"acceptedCallsiteCount":1,"delaySlotReadsV0":delay_reads,"delaySlotWritesV0":delay_writes,
                    "postCallInstructionCountToFirstUse":scanned,"firstReturnUseClass":None,
                    "returnValueClobberedBeforeUse":False,"roleEarned":False,"reason":"control_transfer_before_v0_use"}
    return {"acceptedCallsiteCount":1,"delaySlotReadsV0":delay_reads,"delaySlotWritesV0":delay_writes,
            "postCallInstructionCountToFirstUse":scanned,"firstReturnUseClass":None,
            "returnValueClobberedBeforeUse":False,"roleEarned":False,"reason":"function_end_before_v0_use"}

def classify(r:dict)->str:
    if r.get("roleEarned"): return "E2_D19C_SVCTL_READ_RETURN_USE_ROLE_EARNED"
    if r.get("acceptedCallsiteCount")==1: return "E2_D19C_SVCTL_READ_RETURN_USE_PARTIAL"
    return "E2_D19C_SVCTL_READ_CALLSITE_NOT_UNIQUE"

def run_probe(args):
    work=pathlib.Path(args.work_dir).resolve()
    fw=work/"firmware.image"; payload=work/"payload"; roots=work/"roots"; scratch=work/"scratch"
    for p in (fw.parent,payload,roots,scratch): p.mkdir(parents=True,exist_ok=True)
    exact=base.download_exact(args.firmware_url,fw,expected_size=args.expected_size,expected_sha256=args.expected_sha256)
    base.extract_outer(fw,payload); rs=base.extract_squashfs_roots(payload,roots,scratch); root=base.select_root(rs)
    svctl=(root/SVCTL.lstrip("/")).resolve()
    objdump=shutil.which(args.objdump)
    if not objdump: raise RuntimeError("objdump unavailable")
    got=d13.readelf_selected_got(svctl)
    r=recover_return_use(svctl,objdump,got)
    return {"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":classify(r),"oracleSatisfied":True,
      "target":{"expectedBytes":args.expected_size,"expectedSha256":args.expected_sha256.lower(),"observedBytes":exact["bytes"],"observedSha256":exact["sha256"]},
      "callerReturnUse":r,
      "interpretationBoundary":{"uniqueAcceptedSvctlReadCallsiteRequired":True,"mipsDelaySlotModeled":True,
        "sameBasicBlockSuccessorOnly":True,"returnRegisterClassOnly":True,"returnValuePublished":False,
        "libcReadOwnershipInferred":False,"responsePayloadPublished":False,"responseFieldLayoutAccepted":False,
        "protocolEnumValuesAccepted":False,"payloadOffsetsAccepted":False,"physicalRouterContact":False,"modifiedHilAuthorized":False},
      "safety":{"rawFirmwarePublished":False,"rootfsPublished":False,"binaryPayloadPublished":False,"rawDisassemblyPublished":False,
        "instructionAddressesPublished":False,"gotOffsetsPublished":False,"wirePayloadPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False}}

def parse_args(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--firmware-url",required=True); p.add_argument("--expected-size",type=int,required=True)
    p.add_argument("--expected-sha256",required=True); p.add_argument("--objdump",default="mips-linux-gnu-objdump")
    p.add_argument("--work-dir",required=True); p.add_argument("--receipt",required=True); return p.parse_args(argv)

def main(argv=None):
    args=parse_args(argv); rp=pathlib.Path(args.receipt); rp.parent.mkdir(parents=True,exist_ok=True)
    try: data=run_probe(args); rc=0
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
              "error":{"type":type(exc).__name__,"message":str(exc)[:1000]}}; rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc
if __name__=="__main__": raise SystemExit(main())
