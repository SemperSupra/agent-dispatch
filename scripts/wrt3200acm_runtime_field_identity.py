#!/usr/bin/env python3
"""Recover bounded caller/consumer evidence for selected 0x706c0 runtime fields."""
from __future__ import annotations
import argparse, importlib.util, json
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

FOCUS={
  "init_214":{"pc":0x22730,"field":"+0x214","role":"initializer"},
  "init_21c":{"pc":0x227f8,"field":"+0x21c","role":"initializer"},
  "init_4c":{"pc":0x2331c,"field":"+0x4c","role":"initializer"},
  "tuple_writer":{"pc":0x2a284,"field":"+0x2/+0x4/+0x6","role":"writer"},
  "enable_21c":{"pc":0x28f68,"field":"+0x21c","role":"crypto-consumer"},
  "setkey_6":{"pc":0x29134,"field":"+0x6","role":"crypto-consumer"},
  "shared_4c":{"pc":0x3fb78,"field":"+0x4c","role":"crypto-consumer"},
}

def elf_low_end(path:Path)->int:
    import struct
    d=path.read_bytes(); ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    ends=[]
    for i in range(pn):
        o=ph+i*pe
        typ,_fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs and va<0x1000000:ends.append(va+fs)
    return max(ends)

def is_prologue(x)->bool:
    mn=x["mnemonic"]; ops=x["operands"]
    if mn=="push" and "lr" in ops:return True
    if mn in {"stmdb","stmfd"} and "sp!" in ops and "lr" in ops:return True
    return False

def is_return(x)->bool:
    mn=x["mnemonic"]; ops=x["operands"]
    return (mn=="bx" and "lr" in ops) or (mn=="pop" and "pc" in ops) or (mn in {"ldmia","ldmfd"} and "pc" in ops)

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    ins=dp.parse_instructions(dp.run_objdump(elf,0,elf_low_end(elf)))
    by_pc={x["address"]:i for i,x in enumerate(ins)}
    records={}
    candidate_starts=set()

    for name,f in FOCUS.items():
        pc=f["pc"]; idx=by_pc.get(pc)
        if idx is None:
            records[name]={**f,"status":"focus-pc-not-decoded"}
            continue
        start_idx=None
        for j in range(idx,max(-1,idx-256),-1):
            if is_prologue(ins[j]):
                start_idx=j;break
        start=ins[start_idx]["address"] if start_idx is not None else None
        if start is not None:candidate_starts.add(start)

        end_idx=None
        if start_idx is not None:
            for j in range(idx,min(len(ins),start_idx+512)):
                if is_return(ins[j]):
                    end_idx=j;break
        local=ins[max(0,idx-24):min(len(ins),idx+25)]
        body=ins[start_idx:min(len(ins),(end_idx+1 if end_idx is not None else start_idx+160))] if start_idx is not None else []
        records[name]={
          **f,"status":"decoded","instruction":ins[idx]["text"],
          "candidate_function_start":start,
          "candidate_function_prologue":ins[start_idx]["text"] if start_idx is not None else None,
          "candidate_return":ins[end_idx]["text"] if end_idx is not None else None,
          "local_context":[x["text"] for x in local],
          "candidate_function_body":[x["text"] for x in body],
        }

    xrefs={s:[] for s in candidate_starts}
    for x in ins:
        if x["mnemonic"] not in {"bl","b"}:continue
        t=dp.branch_target(x)
        if t in xrefs:
            xrefs[t].append({"pc":x["address"],"kind":x["mnemonic"],"text":x["text"]})

    for rec in records.values():
        s=rec.get("candidate_function_start")
        if s is not None:rec["direct_call_or_tail_xrefs"]=xrefs.get(s,[])

    tuple_start=records.get("tuple_writer",{}).get("candidate_function_start")
    tuple_callers=xrefs.get(tuple_start,[]) if tuple_start is not None else []
    report={
      "schema":"wrt8964-runtime-field-identity/v1",
      "focus":records,
      "tuple_writer_function_start":tuple_start,
      "tuple_writer_direct_call_or_tail_xrefs":tuple_callers,
      "classification":{
        "observed":"This report identifies candidate containing functions by nearest preceding ARM save-LR prologue and enumerates direct BL/B xrefs to those starts.",
        "inference_limit":"Function boundaries are heuristic until corroborated by control-flow analysis. Six-byte shape alone is not sufficient to name the +0x2/+0x4/+0x6 tuple as a MAC address.",
        "promotion_gate":"Assign a domain field identity only when caller argument provenance or source correlation agrees with the binary consumer/writer behavior."
      }
    }
    (out/"runtime-field-identity.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "tuple_writer_function_start":hex(tuple_start) if tuple_start is not None else None,
      "tuple_writer_direct_call_or_tail_xrefs":[{"pc":hex(x["pc"]),"kind":x["kind"],"text":x["text"]} for x in tuple_callers],
      "focus":{k:{
        "pc":hex(v["pc"]),"field":v["field"],"role":v["role"],
        "function_start":hex(v["candidate_function_start"]) if v.get("candidate_function_start") is not None else None,
        "xrefs":[{"pc":hex(x["pc"]),"kind":x["kind"],"text":x["text"]} for x in v.get("direct_call_or_tail_xrefs",[])],
        "local":v.get("local_context",[])
      } for k,v in records.items()}
    },indent=2,sort_keys=True))
    return 0 if all(v.get("status")=="decoded" for v in records.values()) else 3

if __name__=="__main__":raise SystemExit(main())
