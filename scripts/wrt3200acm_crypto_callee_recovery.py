#!/usr/bin/env python3
from __future__ import annotations
import argparse, importlib.util, json, re
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P); dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

TARGETS={
  "shared_0x3fb34":(0x3fb34,0x3fd40),
  "set_key_0x44148":(0x44148,0x44230),
  "remove_key_0x44230":(0x44230,0x44380),
}
CRYPTO_VALUES={0,1,2,3,4,5,6,7,8,13,16,24,32,44,64,128,256}

def summarize(text):
    ins=dp.parse_instructions(text); calls=[]; cmps=[]; imms=[]; mem=[]
    for x in ins:
        if x["mnemonic"]=="bl":
            t=dp.branch_target(x)
            if t is not None: calls.append({"at":x["address"],"target":t,"text":x["text"]})
        if x["mnemonic"] in {"cmp","cmn","tst","teq"}:
            cmps.append(x["text"])
        for m in re.finditer(r"#(0x[0-9a-fA-F]+|[0-9]+)",x["operands"]):
            try:
                v=int(m.group(1),0)
                if v in CRYPTO_VALUES: imms.append({"at":x["address"],"value":v,"text":x["text"]})
            except ValueError: pass
        for m in re.finditer(r"\[(r\d+|sp|lr), #([0-9]+)\]",x["operands"]):
            mem.append({"at":x["address"],"base":m.group(1),"offset":int(m.group(2)),"text":x["text"]})
    return {
      "instruction_count":len(ins),
      "calls":calls,
      "unique_call_targets":sorted({c["target"] for c in calls}),
      "compares":cmps,
      "crypto_relevant_immediates":imms,
      "memory_offsets":mem,
      "unique_memory_offsets":sorted({m["offset"] for m in mem}),
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    report={"schema":"wrt8964-crypto-callee-recovery/v1","targets":{}}
    for name,(a,b) in TARGETS.items():
        text=dp.run_objdump(Path(ns.elf),a,b)
        report["targets"][name]={"start":a,"end":b,**summarize(text)}
        (out/f"{name}.txt").write_text(text)
    sets={k:set(v["unique_call_targets"]) for k,v in report["targets"].items()}
    report["shared_next_depth_targets"]=sorted(set.intersection(*sets.values())) if sets else []
    report["guardrail"]="Immediate values are candidate semantic anchors only. Names such as AES/TKIP/WEP require source or signature agreement."
    (out/"crypto-callee-recovery.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:{"calls":[hex(x) for x in v["unique_call_targets"]],"offsets":v["unique_memory_offsets"][:40]} for k,v in report["targets"].items()},indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
