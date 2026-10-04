#!/usr/bin/env python3
"""Strict normalized-dispatch probe for W8964 spectrum/DFS commands.

Proves only local equations of the form:
    normalized_reg = r12 - BASE
    cmp normalized_reg, DELTA
    beq HANDLER
where BASE and DELTA have exact constant provenance and BASE+DELTA is one of
our target host commands.

Unresolved is a valid scientific result; only parser/source invariant failures
are fatal.
"""
from __future__ import annotations
import argparse, importlib.util, json, re
from pathlib import Path
from typing import Any

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
S=importlib.util.spec_from_file_location("dp",P)
if S is None or S.loader is None: raise RuntimeError("dispatch helper unavailable")
dp=importlib.util.module_from_spec(S); S.loader.exec_module(dp)

TARGETS={0x1128:"HOSTCMD_CMD_SET_SPECTRUM_MGMT",0x0120:"HOSTCMD_CMD_802_11H_DETECT_RADAR"}
REG_RE=re.compile(r"^(?:r(?:1[0-2]|[0-9])|lr|ip)$")

def ops(x):
    return [p.strip().lower() for p in x["operands"].split(",")]

def last_write(ins,idx,reg,limit=40):
    reg=reg.lower()
    for j in range(idx-1,max(-1,idx-limit-1),-1):
        o=ops(ins[j])
        if o and o[0]==reg:
            return j,ins[j]
        if ins[j]["mnemonic"]=="b":
            break
    return None,None

def const_value(ins,idx,reg,limit=20):
    j,x=last_write(ins,idx,reg,limit)
    if x is None: return None,None
    o=ops(x)
    if x["mnemonic"] in {"mov","movw"}:
        v=dp.immediate(x)
        if v is not None:
            # Optional immediately-following movt on same register.
            hi=0
            for k in range(j+1,min(idx,j+4)):
                y=ins[k]; oy=ops(y)
                if oy and oy[0]==reg and y["mnemonic"]=="movt":
                    iv=dp.immediate(y)
                    if iv is not None: hi=iv<<16
                    break
                if oy and oy[0]==reg: break
            return hi|v,{"pc":x["address"],"text":x["text"],"movt_high":hi}
    return None,None

def branch_after(ins,idx):
    for j in range(idx+1,min(len(ins),idx+4)):
        x=ins[j]
        if x["mnemonic"]=="beq":
            return {"pc":x["address"],"target":dp.branch_target(x),"text":x["text"]}
        if x["mnemonic"].startswith("b") and x["mnemonic"]!="beq":
            break
    return None

def normalized_definition(ins,cmp_idx,reg):
    j,x=last_write(ins,cmp_idx,reg,48)
    if x is None or x["mnemonic"] not in {"sub","subs","subw"}:
        return None
    o=ops(x)
    if len(o)<3 or o[0]!=reg or o[1]!="r12":
        return None
    base=dp.immediate(x); provenance=None
    if base is not None:
        provenance={"kind":"immediate","value":base,"producer":{"pc":x["address"],"text":x["text"]}}
    elif REG_RE.match(o[2]):
        base,p=const_value(ins,j,o[2])
        if base is not None:
            provenance={"kind":"register-constant","register":o[2],"value":base,"producer":p}
    if base is None: return None
    return {"pc":x["address"],"text":x["text"],"reg":reg,"base":base,"base_provenance":provenance}

def compare_constant(ins,idx,cmp):
    o=ops(cmp)
    if len(o)<2: return None,None
    v=dp.immediate(cmp)
    if v is not None: return v,{"kind":"immediate","value":v}
    if REG_RE.match(o[1]):
        v,p=const_value(ins,idx,o[1])
        if v is not None: return v,{"kind":"register-constant","register":o[1],"value":v,"producer":p}
    return None,None

def recover(ins):
    proofs=[]
    for i,x in enumerate(ins):
        if x["mnemonic"] not in {"cmp","cmn"}: continue
        o=ops(x)
        if len(o)<2 or not REG_RE.match(o[0]) or o[0]=="r12": continue
        br=branch_after(ins,i)
        if not br or br["target"] is None: continue
        nd=normalized_definition(ins,i,o[0])
        if not nd: continue
        delta,dpv=compare_constant(ins,i,x)
        if delta is None: continue
        command=nd["base"]+delta
        if command not in TARGETS: continue
        proofs.append({
          "command":TARGETS[command],"command_id":f"0x{command:04x}",
          "equation":f"0x{nd['base']:x} + 0x{delta:x} = 0x{command:x}",
          "normalization":nd,"compare":{"pc":x["address"],"text":x["text"],"delta":delta,"provenance":dpv},
          "branch":br,
          "context":[z["text"] for z in ins[max(0,nd["pc"] and next(k for k,v in enumerate(ins) if v["address"]==nd["pc"])-5):min(len(ins),i+5)]],
          "confidence":"exact-local-dataflow"
        })
    return proofs

def selftest():
    ins=[
      {"address":0x100,"mnemonic":"movw","operands":"lr, #4353","text":"100: movw lr, #4353"},
      {"address":0x104,"mnemonic":"sub","operands":"r2, r12, lr","text":"104: sub r2, r12, lr"},
      {"address":0x108,"mnemonic":"cmp","operands":"r2, #39","text":"108: cmp r2, #39"},
      {"address":0x10c,"mnemonic":"beq","operands":"0x200","text":"10c: beq 0x200"},
      {"address":0x110,"mnemonic":"sub","operands":"r3, r12, #256","text":"110: sub r3, r12, #256"},
      {"address":0x114,"mnemonic":"cmp","operands":"r3, #32","text":"114: cmp r3, #32"},
      {"address":0x118,"mnemonic":"beq","operands":"0x300","text":"118: beq 0x300"},
    ]
    got=recover(ins)
    pairs={(x["command_id"],x["branch"]["target"]) for x in got}
    assert ("0x1128",0x200) in pairs and ("0x0120",0x300) in pairs, pairs

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    selftest()
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    text=dp.run_objdump(Path(ns.elf),dp.DISPATCH_START,dp.DISPATCH_END)
    ins=dp.parse_instructions(text)
    proofs=recover(ins)
    by={f"0x{x:04x}":[] for x in TARGETS}
    for p in proofs: by[p["command_id"]].append(p)
    report={
      "schema":"wrt8964-spectrum-dfs-normalized-dispatch/v1",
      "firmware_sha256":"ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751",
      "dispatcher":{"start":dp.DISPATCH_START,"end":dp.DISPATCH_END,"instruction_count":len(ins)},
      "targets":{f"0x{k:04x}":{"name":v,"status":"proven-normalized-mapping" if by[f"0x{k:04x}"] else "unresolved","proofs":by[f"0x{k:04x}"]} for k,v in TARGETS.items()},
      "guardrail":"Only exact local subtraction+compare+BEQ dataflow is accepted. Unresolved does not imply command absence."
    }
    (out/"spectrum-dfs-normalized-dispatch.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:v["status"] for k,v in report["targets"].items()},indent=2,sort_keys=True))
    return 0
if __name__=="__main__": raise SystemExit(main())
