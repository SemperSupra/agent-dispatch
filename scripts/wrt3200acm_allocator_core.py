#!/usr/bin/env python3
"""Recover the core allocator at 0x2254 used by W8964 runtime-state initialization."""
from __future__ import annotations
import argparse, importlib.util, json, re, struct
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

START=0x2254
END=0x23a8
WRAPPER_LITERAL_SLOTS=(0x2840,0x2858)

def read_u32(elf:Path,address:int)->int:
    d=elf.read_bytes()
    ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    for i in range(pn):
        o=ph+i*pe
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and va<=address and address+4<=va+fs:
            return struct.unpack_from("<I",d,fo+(address-va))[0]
    raise ValueError(f"0x{address:x} not file-backed")

def summarize(text:str):
    ins=dp.parse_instructions(text)
    calls=[]; branches=[]; mem=[]; imms=[]; returns=[]; pc_literals=[]
    for x in ins:
        mn=x["mnemonic"]; ops=x["operands"]
        if mn=="bl":
            t=dp.branch_target(x)
            if t is not None:calls.append({"pc":x["address"],"target":t,"text":x["text"]})
        elif mn.startswith("b"):
            t=dp.branch_target(x)
            if t is not None:branches.append({"pc":x["address"],"mnemonic":mn,"target":t,"text":x["text"]})
        for m in re.finditer(r"\[(r(?:1[0-2]|[0-9])|sp|lr)(?:, #([0-9]+))?\]",ops):
            mem.append({"pc":x["address"],"base":m.group(1),"offset":int(m.group(2) or "0"),"mnemonic":mn,"text":x["text"]})
        for m in re.finditer(r"#(0x[0-9a-fA-F]+|[0-9]+)",ops):
            try: imms.append({"pc":x["address"],"value":int(m.group(1),0),"text":x["text"]})
            except ValueError: pass
        m=re.search(r"@\s*0x([0-9a-fA-F]+)",x["text"])
        if m: pc_literals.append({"pc":x["address"],"slot":int(m.group(1),16),"text":x["text"]})
        if (mn=="bx" and "lr" in ops) or (mn=="pop" and "pc" in ops):
            returns.append(x["text"])
    return {
      "instruction_count":len(ins),
      "direct_calls":calls,
      "unique_call_targets":sorted({c["target"] for c in calls}),
      "branches":branches,
      "back_edges":[b for b in branches if b["target"]<b["pc"]],
      "memory_accesses":mem,
      "immediates":imms,
      "pc_relative_literals":pc_literals,
      "return_sites":returns,
      "instructions":ins,
    }

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    text=dp.run_objdump(elf,START,END)
    rec=summarize(text)
    report={
      "schema":"wrt8964-runtime-allocator-core/v1",
      "start":START,"end":END,
      "wrapper_context_literals":{f"0x{x:x}":f"0x{read_u32(elf,x):08x}" for x in WRAPPER_LITERAL_SLOTS},
      "core":rec,
      "questions":{
        "returns_zeroed_memory":"unresolved",
        "alignment_guarantee":"unresolved",
        "allocation_failure_path":"recover from branch/call graph",
        "allocator_contexts":"wrappers 0x23a8 and 0x24e0 supply different fixed context literals before calling 0x2254"
      },
      "guardrail":"0x2254 is called by both observed allocation wrappers. This static pass does not name it malloc/calloc or assert zeroing until machine-code data flow proves those properties."
    }
    (out/"allocator-core-0x2254.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    (out/"allocator-core-0x2254.txt").write_text(text)
    print(json.dumps({
      "instructions":rec["instruction_count"],
      "wrapper_context_literals":report["wrapper_context_literals"],
      "calls":[hex(x) for x in rec["unique_call_targets"]],
      "back_edges":[{"pc":hex(x["pc"]),"target":hex(x["target"])} for x in rec["back_edges"]],
      "returns":rec["return_sites"],
      "memory_offsets":sorted({x["offset"] for x in rec["memory_accesses"]})[:100],
      "interesting_immediates":[hex(x["value"]) for x in rec["immediates"] if x["value"] in {4,8,16,32,64,128,256,4096,0xffff}][:80]
    },indent=2,sort_keys=True))
    return 0 if rec["instruction_count"]>0 and rec["return_sites"] else 3

if __name__=="__main__": raise SystemExit(main())
