#!/usr/bin/env python3
from __future__ import annotations
import argparse, importlib.util, json, re
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P); dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)
HELPERS={"enable":(0x28f54,0x29070),"remove":(0x29070,0x29114),"set_key":(0x29114,0x29540)}

def summarize(text:str):
    ins=dp.parse_instructions(text)
    calls=[]; branches=[]; mem=[]; imms=[]
    for x in ins:
        m=x["mnemonic"]; ops=x["operands"]
        if m=="bl":
            t=dp.branch_target(x)
            if t is not None: calls.append({"at":x["address"],"target":t,"text":x["text"]})
        elif m.startswith("b"):
            t=dp.branch_target(x)
            if t is not None: branches.append({"at":x["address"],"mnemonic":m,"target":t,"text":x["text"]})
        for z in re.finditer(r"\[(r\d+|sp|lr), #([0-9]+)\]",ops):
            mem.append({"at":x["address"],"base":z.group(1),"offset":int(z.group(2)),"text":x["text"]})
        for z in re.finditer(r"#(0x[0-9a-fA-F]+|[0-9]+)",ops):
            try: imms.append({"at":x["address"],"value":int(z.group(1),0),"text":x["text"]})
            except ValueError: pass
    return {
      "instruction_count":len(ins),
      "calls":calls,
      "branches":branches[:400],
      "memory_offsets":mem[:800],
      "immediates":imms[:800],
      "unique_call_targets":sorted({c["target"] for c in calls}),
      "unique_offsets":sorted({m["offset"] for m in mem}),
    }

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    report={"schema":"wrt8964-crypto-helper-recovery/v1","helpers":{}}
    for name,(a,b) in HELPERS.items():
        text=dp.run_objdump(Path(ns.elf),a,b)
        report["helpers"][name]={"start":a,"end":b,**summarize(text)}
        (out/f"helper-{name}.txt").write_text(text)
    # Shared callees are useful for prioritizing common state/runtime dependencies.
    target_sets={k:set(v["unique_call_targets"]) for k,v in report["helpers"].items()}
    common=set.intersection(*target_sets.values()) if target_sets else set()
    report["common_call_targets"]=sorted(common)
    report["guardrail"]="Call targets and offsets are observed. Crypto semantic names remain hypotheses until correlated with exact/donor source evidence."
    (out/"crypto-helper-recovery.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:{"calls":len(v["calls"]),"targets":[hex(x) for x in v["unique_call_targets"]]} for k,v in report["helpers"].items()},indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
