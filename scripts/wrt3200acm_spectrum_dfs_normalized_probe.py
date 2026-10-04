#!/usr/bin/env python3
"""Provenance-aware normalized dispatcher recovery for bounded W8964 commands.

Accept a mapping only when the target firmware proves:
  original command r12 - explicit constant BASE -> derived register
  compare derived register against exact DELTA
  BEQ -> handler
and the same algorithm first reproduces already-accepted dispatcher mappings.

Unresolved is a valid scientific result.  Algorithm qualification failure is
an infrastructure/evidence-harness failure and returns non-zero.
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
KNOWN={0x1122:("HOSTCMD_CMD_UPDATE_ENCRYPTION",0x37b84),0x1143:("HOSTCMD_CMD_GET_SEQNO",0x36ff0),0x010a:("HOSTCMD_CMD_SET_RF_CHANNEL",0x37984)}
COMMANDS={**TARGETS,**{k:v[0] for k,v in KNOWN.items()}}
REG_RE=re.compile(r"^(?:r(?:1[0-2]|[0-9])|lr|ip)$")

def ops(x): return [p.strip().lower() for p in x["operands"].split(",")]

def last_write(ins,idx,reg,limit=96):
    reg=reg.lower()
    for j in range(idx-1,max(-1,idx-limit-1),-1):
        o=ops(ins[j])
        if o and o[0]==reg:
            return j,ins[j]
    return None,None

def const_value(ins,idx,reg,limit=24):
    j,x=last_write(ins,idx,reg,limit)
    if x is None: return None,None
    o=ops(x)
    if x["mnemonic"] in {"mov","movw"}:
        v=dp.immediate(x)
        if v is not None:
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
        if x["mnemonic"].startswith("b") and x["mnemonic"]!="beq": break
    return None

def normalized_definition(ins,cmp_idx,reg):
    j,x=last_write(ins,cmp_idx,reg,96)
    if x is None or x["mnemonic"] not in {"sub","subs","subw"}: return None
    o=ops(x)
    if len(o)<3 or o[0]!=reg or o[1]!="r12": return None
    base=dp.immediate(x); provenance=None
    if base is not None:
        provenance={"kind":"immediate","value":base,"producer":{"pc":x["address"],"text":x["text"]}}
    elif REG_RE.match(o[2]):
        base,p=const_value(ins,j,o[2])
        if base is not None:
            provenance={"kind":"register-constant","register":o[2],"value":base,"producer":p}
    if base is None: return None
    return {"pc":x["address"],"index":j,"text":x["text"],"reg":reg,"base":base,"base_provenance":provenance}

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
    # Base equality: SUBS derived,r12,BASE immediately followed by BEQ.
    for i,x in enumerate(ins):
        if x["mnemonic"]=="subs":
            o=ops(x)
            if len(o)>=3 and o[1]=="r12":
                base=dp.immediate(x); prov=None
                if base is None and REG_RE.match(o[2]):
                    base,prov=const_value(ins,i,o[2])
                br=branch_after(ins,i)
                if base in COMMANDS and br and br["target"] is not None:
                    proofs.append({"command":COMMANDS[base],"command_id":f"0x{base:04x}","equation":f"0x{base:x} + 0 = 0x{base:x}",
                      "normalization":{"pc":x["address"],"text":x["text"],"reg":o[0],"base":base,"base_provenance":prov or {"kind":"immediate","value":base}},
                      "compare":{"pc":x["address"],"text":x["text"],"delta":0,"provenance":{"kind":"zero-result-flags"}},
                      "branch":br,"confidence":"exact-local-dataflow"})
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
        if command not in COMMANDS: continue
        proofs.append({"command":COMMANDS[command],"command_id":f"0x{command:04x}","equation":f"0x{nd['base']:x} + 0x{delta:x} = 0x{command:x}",
          "normalization":nd,"compare":{"pc":x["address"],"text":x["text"],"delta":delta,"provenance":dpv},
          "branch":br,"confidence":"exact-local-dataflow"})
    uniq={}
    for p in proofs:
        key=(p["command_id"],p["branch"]["target"],p["normalization"]["pc"],p["compare"]["pc"])
        uniq[key]=p
    return sorted(uniq.values(),key=lambda p:(p["command_id"],p["branch"]["target"] or 0))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    text=dp.run_objdump(Path(ns.elf),dp.DISPATCH_START,dp.DISPATCH_END)
    ins=dp.parse_instructions(text)
    proofs=recover(ins)
    by={f"0x{x:04x}":[p for p in proofs if p["command_id"]==f"0x{x:04x}"] for x in COMMANDS}
    validation={}
    for c,(name,target) in KNOWN.items():
        matches=[p for p in by[f"0x{c:04x}"] if p["branch"]["target"]==target]
        validation[f"0x{c:04x}"]={"name":name,"expected_target":f"0x{target:x}","passed":bool(matches),"matches":matches}
    qualified=all(v["passed"] for v in validation.values())
    targets={}
    for c,name in TARGETS.items():
        hs=by[f"0x{c:04x}"] if qualified else []
        targets[f"0x{c:04x}"]={"name":name,"status":"proven-normalized-mapping" if len(hs)==1 else ("ambiguous" if len(hs)>1 else "unresolved"),"proofs":hs,"raw_proofs_before_validation":by[f"0x{c:04x}"]}
    report={"schema":"wrt8964-spectrum-dfs-normalized-dispatch/v2","firmware_sha256":"ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751",
      "dispatcher":{"start":dp.DISPATCH_START,"end":dp.DISPATCH_END,"instruction_count":len(ins)},
      "algorithm_qualified":qualified,"known_validation":validation,"targets":targets,
      "guardrail":"Only exact local subtraction+compare+BEQ dataflow is accepted, and target mappings are emitted only after already-accepted mappings reproduce. Unresolved does not imply command absence."}
    (out/"spectrum-dfs-normalized-dispatch.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"algorithm_qualified":qualified,"known":{k:v["passed"] for k,v in validation.items()},"targets":{k:v["status"] for k,v in targets.items()}},indent=2,sort_keys=True))
    return 0 if qualified else 3
if __name__=="__main__": raise SystemExit(main())
