#!/usr/bin/env python3
"""Recover the local function family around the 0x706c0+0x4c MAC-keyed hash table."""
from __future__ import annotations
import argparse, importlib.util, json, re
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

START=0x3fb20
END=0x3fe80
KNOWN_LOOKUP=0x3fb34

def is_return(x):
    mn=x["mnemonic"]; ops=x["operands"]
    return (mn=="bx" and "lr" in ops) or (mn=="pop" and "pc" in ops) or (mn in {"ldmia","ldmfd"} and "pc" in ops)

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    text=dp.run_objdump(Path(ns.elf),START,END)
    ins=dp.parse_instructions(text)

    bl_targets={}
    xrefs={}
    for x in ins:
        if x["mnemonic"] in {"bl","b"}:
            t=dp.branch_target(x)
            if t is not None:
                xrefs.setdefault(t,[]).append({"pc":x["address"],"kind":x["mnemonic"],"text":x["text"]})
                if x["mnemonic"]=="bl": bl_targets.setdefault(t,[]).append(x["address"])

    bucket_access=[]
    anchor_literals=[]
    node_fields={}
    for x in ins:
        ops=x["operands"]
        if "#76" in ops or "0x4c" in ops:
            bucket_access.append({"pc":x["address"],"mnemonic":x["mnemonic"],"text":x["text"]})
        if "0x706c0" in x["text"].lower():
            anchor_literals.append({"pc":x["address"],"text":x["text"]})
        for m in re.finditer(r"\[[^\]]+, #([0-9]+)\]",ops):
            off=int(m.group(1))
            if off <= 128:
                node_fields.setdefault(off,[]).append({"pc":x["address"],"mnemonic":x["mnemonic"],"text":x["text"]})

    # Segment the local region at returns.  These are bounded candidate leaf/body
    # spans, not authoritative function boundaries by themselves.
    spans=[]; start_i=0
    for i,x in enumerate(ins):
        if is_return(x):
            spans.append({
              "start":ins[start_i]["address"] if start_i<len(ins) else None,
              "end":x["address"],
              "instructions":[y["text"] for y in ins[start_i:i+1]],
            })
            start_i=i+1
    if start_i<len(ins):
        spans.append({"start":ins[start_i]["address"],"end":ins[-1]["address"],"instructions":[y["text"] for y in ins[start_i:]]})

    report={
      "schema":"wrt8964-runtime-hash-object-recovery/v1",
      "region":{"start":START,"end":END},
      "known_lookup":KNOWN_LOOKUP,
      "bucket_table_accesses":bucket_access,
      "anchor_literal_lines":anchor_literals,
      "local_bl_targets":{f"0x{k:x}":[f"0x{x:x}" for x in v] for k,v in sorted(bl_targets.items())},
      "local_xrefs":{f"0x{k:x}":v for k,v in sorted(xrefs.items())},
      "node_field_accesses":{str(k):v for k,v in sorted(node_fields.items())},
      "return_delimited_spans":spans,
      "full_disassembly":[x["text"] for x in ins],
      "guardrail":"This is a bounded local disassembly/xref inventory. Return-delimited spans and adjacency are discovery evidence only; object/function identities require data-flow corroboration."
    }
    (out/"runtime-hash-object-recovery.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "bucket_table_accesses":[{"pc":hex(x["pc"]),"text":x["text"]} for x in bucket_access],
      "anchor_literals":[{"pc":hex(x["pc"]),"text":x["text"]} for x in anchor_literals],
      "local_bl_targets":report["local_bl_targets"],
      "spans":[{"start":hex(s["start"]) if s["start"] is not None else None,"end":hex(s["end"]),"instructions":s["instructions"]} for s in spans],
    },indent=2,sort_keys=True))
    return 0 if bucket_access else 3

if __name__=="__main__": raise SystemExit(main())
