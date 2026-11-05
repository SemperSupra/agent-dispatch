#!/usr/bin/env python3
"""Recover the local function family around the 0x706c0+0x4c MAC-keyed hash table."""
from __future__ import annotations
import argparse, importlib.util, json, re, urllib.request
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

START=0x3fb20
END=0x3fe80
HOSTCMD_REF="db97edf20fadea2617805006f5230665fadc6a8c"
HOSTCMD_URL=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{HOSTCMD_REF}/hif/hostcmd.h"
KNOWN_LOOKUP=0x3fb34
TARGETS={
  "lookup_a":0x3fb34,
  "lookup_b":0x3fbe4,
  "insert":0x3fc94,
  "remove":0x3fd34,
}

def fetch_text(url:str)->str:
    req=urllib.request.Request(url,headers={"User-Agent":"SemperSupra-WRT-hash-object/1.0"})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")

def elf_low_end(path:Path)->int:
    import struct
    d=path.read_bytes(); ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    ends=[]
    for i in range(pn):
        o=ph+i*pe
        typ,_fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs and va<0x1000000: ends.append(va+fs)
    return max(ends)

def read_u32(path:Path,address:int)->int:
    import struct
    d=path.read_bytes(); ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    for i in range(pn):
        o=ph+i*pe
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and va<=address and address+4<=va+fs:
            return struct.unpack_from("<I",d,fo+address-va)[0]
    raise ValueError(hex(address))

def is_return(x):
    mn=x["mnemonic"]; ops=x["operands"]
    return (mn=="bx" and "lr" in ops) or (mn=="pop" and "pc" in ops) or (mn in {"ldmia","ldmfd"} and "pc" in ops)

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    text=dp.run_objdump(Path(ns.elf),START,END)
    ins=dp.parse_instructions(text)
    hostcmd_src=fetch_text(HOSTCMD_URL)
    source_set_new_stn=bool(re.search(r"^\s*#define\s+HOSTCMD_CMD_SET_NEW_STN\s+0x1111\b",hostcmd_src,re.M))
    dispatcher=dp.parse_instructions(dp.run_objdump(Path(ns.elf),0x36454,0x390ec))
    set_new_stn_normalized_region_text=dp.run_objdump(Path(ns.elf),0x365e0,0x366ec)
    set_new_stn_normalized_region=dp.parse_instructions(set_new_stn_normalized_region_text)
    recovered=dp.recover_cases(dispatcher,{0x1111:"HOSTCMD_CMD_SET_NEW_STN"})
    dispatch_immediate_context=[]
    dispatch_r12_context=[]
    dispatch_table_context=[]
    for i,x in enumerate(dispatcher):
        imm=dp.immediate(x)
        if imm in {0x1100,0x1101,0x1111,0x1114,0x1121,0x1122,0x1125}:
            dispatch_immediate_context.append({
              "pc":x["address"],"immediate":imm,"text":x["text"],
              "context":[y["text"] for y in dispatcher[max(0,i-10):min(len(dispatcher),i+12)]],
            })
        if "r12" in x["operands"].lower() and x["mnemonic"] in {"cmp","cmn","sub","subs","subw","and","ands","bic","mov","movw"}:
            dispatch_r12_context.append({
              "pc":x["address"],"text":x["text"],
              "context":[y["text"] for y in dispatcher[max(0,i-5):min(len(dispatcher),i+7)]],
            })
        if ("pc" in x["operands"].lower() and x["mnemonic"] in {"ldr","add","mov"}) or x["mnemonic"] in {"tbb","tbh"}:
            dispatch_table_context.append({
              "pc":x["address"],"text":x["text"],
              "context":[y["text"] for y in dispatcher[max(0,i-8):min(len(dispatcher),i+10)]],
            })
    set_new_stn_case=recovered[0] if recovered else None
    set_new_stn_handler=set_new_stn_case.get("branch_target") if set_new_stn_case else None
    handler_ins=[]
    handler_calls=[]
    if set_new_stn_handler is not None:
        handler_ins=dp.parse_instructions(dp.run_objdump(Path(ns.elf),set_new_stn_handler,set_new_stn_handler+0x900))
        for x in handler_ins:
            if x["mnemonic"]=="bl":
                t=dp.branch_target(x)
                if t is not None:
                    handler_calls.append({"pc":x["address"],"target":t,"text":x["text"]})
    whole=dp.parse_instructions(dp.run_objdump(Path(ns.elf),0,elf_low_end(Path(ns.elf))))
    whole_by_pc={x["address"]:i for i,x in enumerate(whole)}
    target_xrefs={name:[] for name in TARGETS}
    for x in whole:
        if x["mnemonic"] not in {"bl","b"}: continue
        t=dp.branch_target(x)
        for name,target in TARGETS.items():
            if t==target:
                idx=whole_by_pc[x["address"]]
                target_xrefs[name].append({
                  "pc":x["address"],"kind":x["mnemonic"],"text":x["text"],
                  "context":[y["text"] for y in whole[max(0,idx-20):min(len(whole),idx+5)]],
                })

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
      "schema":"wrt8964-runtime-hash-object-recovery/v5",
      "region":{"start":START,"end":END},
      "known_lookup":KNOWN_LOOKUP,
      "set_new_stn_source_contract":{"ref":HOSTCMD_REF,"url":HOSTCMD_URL,"macro_0x1111":source_set_new_stn},
      "set_new_stn_dispatch_case":set_new_stn_case,
      "set_new_stn_normalized_region":[x["text"] for x in set_new_stn_normalized_region],
      "dispatch_immediate_context":dispatch_immediate_context,
      "dispatch_r12_context":dispatch_r12_context,
      "dispatch_table_context":dispatch_table_context,
      "set_new_stn_handler_calls":handler_calls,
      "set_new_stn_handler_context":[x["text"] for x in handler_ins],
      "target_xrefs":target_xrefs,
      "literal_values":{"0x3ff30":read_u32(Path(ns.elf),0x3ff30),"0x3ff34":read_u32(Path(ns.elf),0x3ff34)},
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
      "set_new_stn_dispatch":{
        "source_macro_0x1111":source_set_new_stn,
        "case":set_new_stn_case,
        "handler":hex(set_new_stn_handler) if set_new_stn_handler is not None else None,
        "handler_calls":[{"pc":hex(x["pc"]),"target":hex(x["target"]),"text":x["text"]} for x in handler_calls],
        "normalized_region":[x["text"] for x in set_new_stn_normalized_region],
        "immediate_context":[{"pc":hex(x["pc"]),"immediate":hex(x["immediate"]),"text":x["text"],"context":x["context"]} for x in dispatch_immediate_context],
        "r12_context":dispatch_r12_context,
        "table_context":dispatch_table_context,
      },
      "target_xrefs":{k:[{"pc":hex(x["pc"]),"kind":x["kind"],"text":x["text"],"context":x["context"]} for x in v] for k,v in target_xrefs.items()},
      "literal_values":{"0x3ff30":hex(read_u32(Path(ns.elf),0x3ff30)),"0x3ff34":hex(read_u32(Path(ns.elf),0x3ff34))},
      "bucket_table_accesses":[{"pc":hex(x["pc"]),"text":x["text"]} for x in bucket_access],
      "anchor_literals":[{"pc":hex(x["pc"]),"text":x["text"]} for x in anchor_literals],
      "local_bl_targets":report["local_bl_targets"],
      "spans":[{"start":hex(s["start"]) if s["start"] is not None else None,"end":hex(s["end"]),"instructions":s["instructions"]} for s in spans],
    },indent=2,sort_keys=True))
    return 0 if bucket_access and source_set_new_stn else 3

if __name__=="__main__": raise SystemExit(main())
