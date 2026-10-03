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

CALL_FOCUS={
  "tuple_writer_caller":0x37168,
  "lookup_from_enable":0x29028,
  "lookup_from_remove_a":0x290b8,
  "lookup_from_remove_b":0x290dc,
  "lookup_from_setkey_a":0x29208,
  "lookup_from_setkey_b":0x292c8,
  "lookup_from_setkey_c":0x293a0,
  "lookup_from_wrapper":0x37bd0,
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
    return (mn=="push" and "lr" in ops) or (mn in {"stmdb","stmfd"} and "sp!" in ops and "lr" in ops)

def is_return(x)->bool:
    mn=x["mnemonic"]; ops=x["operands"]
    return (mn=="bx" and "lr" in ops) or (mn=="pop" and "pc" in ops) or (mn in {"ldmia","ldmfd"} and "pc" in ops)

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    ins=dp.parse_instructions(dp.run_objdump(elf,0,elf_low_end(elf)))
    by_pc={x["address"]:i for i,x in enumerate(ins)}

    # Direct BL targets are the strongest cheap function-start evidence available
    # in this linear disassembly.  Keep tail-B xrefs for caller evidence but do
    # not use arbitrary B targets to establish a function boundary.
    bl_xrefs={}
    all_xrefs={}
    for x in ins:
        if x["mnemonic"] not in {"bl","b"}:continue
        t=dp.branch_target(x)
        if t is None:continue
        rec={"pc":x["address"],"kind":x["mnemonic"],"text":x["text"]}
        all_xrefs.setdefault(t,[]).append(rec)
        if x["mnemonic"]=="bl":bl_xrefs.setdefault(t,[]).append(rec)
    bl_targets=set(bl_xrefs)

    records={}
    candidate_starts=set()
    for name,f in FOCUS.items():
        pc=f["pc"]; idx=by_pc.get(pc)
        if idx is None:
            records[name]={**f,"status":"focus-pc-not-decoded"};continue

        start_idx=None; basis=None
        direct=[a for a in bl_targets if a<=pc and pc-a<=0x800 and a in by_pc]
        if direct:
            start=max(direct); start_idx=by_pc[start]; basis="nearest-preceding-direct-bl-target"
        else:
            # Leaf functions may have no stack/LR prologue.  A return directly
            # before the focused block is stronger than borrowing an older
            # prologue across that control-flow barrier.
            for j in range(idx-1,max(-1,idx-256),-1):
                if is_return(ins[j]) and j+1<len(ins):
                    start_idx=j+1;basis="instruction-after-preceding-return";break
            if start_idx is None:
                for j in range(idx,max(-1,idx-256),-1):
                    if is_prologue(ins[j]):
                        start_idx=j;basis="nearest-save-lr-prologue";break

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
          "candidate_function_start":start,"boundary_basis":basis,
          "candidate_function_entry":ins[start_idx]["text"] if start_idx is not None else None,
          "candidate_return":ins[end_idx]["text"] if end_idx is not None else None,
          "local_context":[x["text"] for x in local],
          "candidate_function_body":[x["text"] for x in body],
        }

    for rec in records.values():
        s=rec.get("candidate_function_start")
        if s is not None:rec["direct_call_or_tail_xrefs"]=all_xrefs.get(s,[])

    callsite_context={}
    for name,pc in CALL_FOCUS.items():
        idx=by_pc.get(pc)
        callsite_context[name]={
          "pc":pc,
          "instruction":ins[idx]["text"] if idx is not None else None,
          "context":[x["text"] for x in ins[max(0,idx-24):min(len(ins),idx+7)]] if idx is not None else [],
        }

    tuple_start=records.get("tuple_writer",{}).get("candidate_function_start")
    tuple_callers=all_xrefs.get(tuple_start,[]) if tuple_start is not None else []
    report={
      "schema":"wrt8964-runtime-field-identity/v4",
      "focus":records,
      "tuple_writer_function_start":tuple_start,
      "tuple_writer_direct_call_or_tail_xrefs":tuple_callers,
      "callsite_context":callsite_context,
      "structural_promotions":{
        "0x4c":{
          "classification":"observed-plus-bounded-inference",
          "allocation_bytes":4084,
          "bucket_width_bytes":4,
          "bucket_count":1021,
          "hash_modulus":1021,
          "lookup_function":0x3fb34,
          "node_next_offset":0,
          "node_return_payload_offset":4,
          "node_six_byte_key_offset":8,
          "node_discriminator_offset":14,
          "update_encryption_discriminator":1,
          "update_encryption_key_provenance":"enable/remove/set-key helpers pass their six-byte MAC-address argument as r1 and constant 1 as r0 before calling 0x3fb34",
          "inference":"0x706c0+0x4c is a 1021-bucket chained lookup table keyed by a six-byte MAC address plus a one-byte discriminator for UPDATE_ENCRYPTION paths. The domain identity of the returned object remains unassigned."
        },
        "0x21c":{
          "classification":"observed-plus-bounded-inference",
          "allocation_bytes":1088,
          "stride_bytes":64,
          "allocated_stride_slots":17,
          "tuple_writer_function":0x2a23c,
          "tuple_writer_valid_indices":"0..15",
          "tuple_bytes_copied":6,
          "inference":"The +0x21c region is 64-byte-strided storage; 0x2a23c accepts indices below 16 and copies a six-byte tuple into the selected entry. The 17th allocated stride is not explained by this writer."
        }
      },
      "classification":{
        "observed":"Candidate boundaries prefer the nearest preceding direct BL target. Leaf blocks without a direct BL target begin after the nearest preceding return; save-LR prologues are fallback only. Direct BL/B xrefs to the selected start are enumerated.",
        "inference_limit":"Function boundaries remain bounded static-analysis candidates. Six-byte shape alone is not sufficient to name the +0x2/+0x4/+0x6 tuple as a MAC address.",
        "promotion_gate":"Assign a domain field identity only when caller argument provenance or source correlation agrees with the binary consumer/writer behavior."
      }
    }
    (out/"runtime-field-identity.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "tuple_writer_function_start":hex(tuple_start) if tuple_start is not None else None,
      "callsite_context":{k:{"pc":hex(v["pc"]),"instruction":v["instruction"],"context":v["context"]} for k,v in callsite_context.items()},
      "tuple_writer_direct_call_or_tail_xrefs":[{"pc":hex(x["pc"]),"kind":x["kind"],"text":x["text"]} for x in tuple_callers],
      "focus":{k:{
        "pc":hex(v["pc"]),"field":v["field"],"role":v["role"],
        "function_start":hex(v["candidate_function_start"]) if v.get("candidate_function_start") is not None else None,
        "boundary_basis":v.get("boundary_basis"),
        "xrefs":[{"pc":hex(x["pc"]),"kind":x["kind"],"text":x["text"]} for x in v.get("direct_call_or_tail_xrefs",[])],
        "local":v.get("local_context",[])
      } for k,v in records.items()}
    },indent=2,sort_keys=True))
    return 0 if all(v.get("status")=="decoded" for v in records.values()) else 3

if __name__=="__main__":raise SystemExit(main())
