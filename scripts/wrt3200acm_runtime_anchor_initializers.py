#!/usr/bin/env python3
"""Recover initializer/writer semantics for the 0x706c0 runtime anchor fields used by UPDATE_ENCRYPTION."""
from __future__ import annotations
import argparse, importlib.util, json, re
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

ANCHOR=0x706c0
TARGETS={
  "pool_214": {"writer_pc":0x22730,"offset":0x214,"window":(0x22670,0x227a0)},
  "pool_21c": {"writer_pc":0x227f8,"offset":0x21c,"window":(0x22790,0x22820)},
  "pool_208": {"writer_pc":0x22828,"offset":0x208,"window":(0x22810,0x22890)},
  "state_d8": {"writer_pc":0x22ce0,"offset":0xd8,"window":(0x22c60,0x22d50)},
  "table_4c": {"writer_pc":0x2331c,"offset":0x4c,"window":(0x23280,0x23390)},
  "halfwords_0_6": {"writer_pc":0x2a284,"offset":0x2,"window":(0x2a210,0x2a2d0)},
}

def summarize(text:str, writer_pc:int)->dict:
    ins=dp.parse_instructions(text)
    calls=[]; branches=[]; writer=None
    immediates=[]; anchor_literals=[]
    for x in ins:
        if x["address"]==writer_pc: writer=x
        if x["mnemonic"]=="bl":
            t=dp.branch_target(x)
            if t is not None:calls.append({"pc":x["address"],"target":t,"text":x["text"]})
        elif x["mnemonic"].startswith("b"):
            t=dp.branch_target(x)
            if t is not None:branches.append({"pc":x["address"],"mnemonic":x["mnemonic"],"target":t,"text":x["text"]})
        for m in re.finditer(r"#(0x[0-9a-fA-F]+|[0-9]+)",x["operands"]):
            try:
                v=int(m.group(1),0)
                if v>=16:immediates.append({"pc":x["address"],"value":v,"text":x["text"]})
            except ValueError:pass
        if f"0x{ANCHOR:x}" in x["text"].lower():
            anchor_literals.append(x["text"])
    # Keep a local instruction slice around writer for manual/data-flow review.
    idx=next((i for i,x in enumerate(ins) if x["address"]==writer_pc),None)
    local=ins[max(0,(idx or 0)-16):min(len(ins),(idx or 0)+17)] if idx is not None else []
    return {
      "instruction_count":len(ins),
      "writer":writer,
      "local_context":local,
      "calls":calls,
      "branches":branches,
      "immediates":immediates,
      "anchor_literal_lines":anchor_literals,
    }

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    report={"schema":"wrt8964-runtime-anchor-initializers/v1","anchor":ANCHOR,"targets":{}}
    for name,t in TARGETS.items():
        a,b=t["window"]
        text=dp.run_objdump(elf,a,b)
        rec={**t,**summarize(text,t["writer_pc"])}
        report["targets"][name]=rec
        (out/f"{name}.txt").write_text(text)
    # Cross-target direct callees are useful for allocator/memset/common-runtime identification.
    all_calls={}
    for name,rec in report["targets"].items():
        for c in rec["calls"]:
            all_calls.setdefault(c["target"],[]).append({"target_name":name,"pc":c["pc"]})
    report["cross_target_callees"]=[
      {"target":k,"sites":v,"fan_in":len(v)} for k,v in sorted(all_calls.items(),key=lambda kv:(-len(kv[1]),kv[0]))
    ]
    report["guardrail"]="Writer PCs are evidence-backed from the selector3 field map. Function identities, allocator names, and semantic field names remain unassigned until call/data-flow evidence supports them."
    (out/"runtime-anchor-initializers.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      name:{
        "writer":rec["writer"]["text"] if rec["writer"] else None,
        "calls":[{"pc":hex(c["pc"]),"target":hex(c["target"])} for c in rec["calls"]],
        "interesting_immediates":[hex(x["value"]) for x in rec["immediates"][:40]],
        "local":[x["text"] for x in rec["local_context"]]
      } for name,rec in report["targets"].items()
    },indent=2,sort_keys=True))
    return 0 if all(x["writer"] is not None for x in report["targets"].values()) else 3

if __name__=="__main__":raise SystemExit(main())
