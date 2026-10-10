#!/usr/bin/env python3
"""Characterize the runtime allocation helpers feeding the 0x706c0 context."""
from __future__ import annotations
import argparse, importlib.util, json, re
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

RANGES={
  "alloc_0x23a8":(0x23a8,0x24e0),
  "alloc_0x24e0":(0x24e0,0x2700),
}

def summary(text):
    ins=dp.parse_instructions(text); calls=[]; branches=[]; mem=[]; imms=[]
    for x in ins:
        if x["mnemonic"]=="bl":
            t=dp.branch_target(x)
            if t is not None:calls.append({"pc":x["address"],"target":t,"text":x["text"]})
        elif x["mnemonic"].startswith("b"):
            t=dp.branch_target(x)
            if t is not None:branches.append({"pc":x["address"],"mnemonic":x["mnemonic"],"target":t,"text":x["text"]})
        for m in re.finditer(r"\[(r(?:1[0-2]|[0-9])|sp|lr)(?:, #([0-9]+))?\]",x["operands"]):
            mem.append({"pc":x["address"],"base":m.group(1),"offset":int(m.group(2) or "0"),"mnemonic":x["mnemonic"],"text":x["text"]})
        for m in re.finditer(r"#(0x[0-9a-fA-F]+|[0-9]+)",x["operands"]):
            try: imms.append({"pc":x["address"],"value":int(m.group(1),0),"text":x["text"]})
            except ValueError:pass
    return {
      "instruction_count":len(ins),
      "direct_calls":calls,
      "unique_call_targets":sorted({x["target"] for x in calls}),
      "branches":branches,
      "memory_accesses":mem,
      "immediates":imms,
      "return_sites":[x["text"] for x in ins if x["mnemonic"]=="bx" and "lr" in x["operands"] or x["mnemonic"]=="pop" and "pc" in x["operands"]],
    }

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    report={"schema":"wrt8964-runtime-allocator-semantics/v1","helpers":{}}
    for name,(a,b) in RANGES.items():
        text=dp.run_objdump(elf,a,b)
        report["helpers"][name]={"start":a,"end":b,**summary(text)}
        (out/f"{name}.txt").write_text(text)
    report["cross_helper_calls"]={
      name:[hex(x) for x in rec["unique_call_targets"]] for name,rec in report["helpers"].items()
    }
    report["guardrail"]="This pass records control/data-flow of the allocation helpers only. Names such as malloc/calloc/zeroing allocator are not assigned until return-value and initialization behavior are proven."
    (out/"runtime-allocator-semantics.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      name:{
        "instructions":rec["instruction_count"],
        "calls":[hex(x) for x in rec["unique_call_targets"]],
        "returns":rec["return_sites"][:20],
        "interesting_immediates":[hex(x["value"]) for x in rec["immediates"] if x["value"] in {4,8,16,32,64,128,256,4096}][:40]
      } for name,rec in report["helpers"].items()
    },indent=2,sort_keys=True))
    return 0

if __name__=="__main__": raise SystemExit(main())
