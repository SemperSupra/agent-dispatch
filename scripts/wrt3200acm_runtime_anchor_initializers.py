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
  "halfwords_2_6": {"writer_pc":0x2a284,"offset":0x2,"window":(0x2a210,0x2a2d0)},
}

EXCLUDED_NON_ANCHOR_CANDIDATES={
  "0x2d3c8":{
    "load_pc":0x2d3a8,"writeback_pc":0x2d3ac,"delta":0x908,
    "effective_base":ANCHOR+0x908,
    "reason":"r1 is changed by address-writeback load at 0x2d3ac before the later store",
  },
  "0x30808":{
    "load_pc":0x307e8,"writeback_pc":0x30800,"delta":0x624,
    "effective_base":ANCHOR+0x624,
    "reason":"r1 is changed by address-writeback load at 0x30800 before the later store",
  },
}

def read_elf_u32(path:Path,address:int)->int:
    d=path.read_bytes()
    if d[:4]!=b"\x7fELF" or d[4]!=1 or d[5]!=1:
        raise ValueError("expected ELF32 little-endian")
    import struct
    phoff=struct.unpack_from("<I",d,28)[0]; ent=struct.unpack_from("<H",d,42)[0]; num=struct.unpack_from("<H",d,44)[0]
    for i in range(num):
        o=phoff+i*ent
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and va<=address and address+4<=va+fs:
            return struct.unpack_from("<I",d,fo+(address-va))[0]
    raise ValueError(f"0x{address:x} not in file-backed load range")

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
      "instructions":ins,
    }

def line_at(targets:dict,name:str,pc:int)->str|None:
    for x in targets[name]["instructions"]:
        if x["address"]==pc:return x["text"]
    return None

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    report={"schema":"wrt8964-runtime-anchor-initializers/v3","anchor":ANCHOR,"targets":{},
      "literal_values":{f"0x{x:x}":f"0x{read_elf_u32(elf,x):08x}" for x in (0x22a1c,0x22a30,0x22a34,0x29bec,0x2a634)}}
    for name,t in TARGETS.items():
        a,b=t["window"]
        text=dp.run_objdump(elf,a,b)
        rec={**t,**summarize(text,t["writer_pc"])}
        report["targets"][name]=rec
        (out/f"{name}.txt").write_text(text)

    all_calls={}
    for name,rec in report["targets"].items():
        for c in rec["calls"]:
            all_calls.setdefault(c["target"],[]).append({"target_name":name,"pc":c["pc"]})
    report["cross_target_callees"]=[
      {"target":k,"sites":v,"fan_in":len(v)} for k,v in sorted(all_calls.items(),key=lambda kv:(-len(kv[1]),kv[0]))
    ]

    report["excluded_non_anchor_candidates"]=EXCLUDED_NON_ANCHOR_CANDIDATES
    report["field_semantics"]={
      "0x2_0x4_0x6":{
        "classification":"observed",
        "width_bits":16,
        "relationship":"three adjacent halfword fields written together from a three-halfword source tuple",
        "writers":[
          {"pc":0x2a284,"offset":0x2,"text":line_at(report["targets"],"halfwords_2_6",0x2a284)},
          {"pc":0x2a28c,"offset":0x4,"text":line_at(report["targets"],"halfwords_2_6",0x2a28c)},
          {"pc":0x2a294,"offset":0x6,"text":line_at(report["targets"],"halfwords_2_6",0x2a294)},
        ],
        "note":"This does not assign domain names to the fields. Offset 0 is deliberately excluded because no exact-anchor writer is accepted by the corrected provenance scan."
      },
      "0x4c":{
        "classification":"observed-plus-bounded-inference",
        "writer_pc":0x2331c,
        "call_pc":0x23314,
        "size_argument_pc":0x23310,
        "size_bytes":0xff4,
        "evidence":[
          line_at(report["targets"],"table_4c",0x23310),
          line_at(report["targets"],"table_4c",0x23314),
          line_at(report["targets"],"table_4c",0x2331c),
        ],
        "inference":"The field receives the return value of helper 0x24e0 immediately after a 4084-byte size is placed in r0. Separate allocator recovery shows helper 0x24e0 calls core 0x2254; the specific subsystem/table identity remains unassigned."
      },
      "0x214":{
        "classification":"observed-plus-shape-candidate",
        "writer_pc":0x22730,
        "call_pc":0x22728,
        "size_argument_pc":0x22724,
        "size_bytes":0x37a0,
        "candidate_record_stride_bytes":32,
        "candidate_record_count":0x37a0//32,
        "evidence":[
          line_at(report["targets"],"pool_214",0x22724),
          line_at(report["targets"],"pool_214",0x22728),
          line_at(report["targets"],"pool_214",0x22730),
          line_at(report["targets"],"pool_214",0x22760),
        ],
        "inference":"The field receives an allocation-like helper return for 14240 bytes. Nearby initialization uses a <<5 address stride, making 445 x 32-byte records a shape candidate, not yet a named structure."
      },
      "0x21c":{
        "classification":"observed-plus-shape-candidate",
        "writer_pc":0x227f8,
        "call_pc":0x227f0,
        "size_argument_pc":0x227ec,
        "size_bytes":0x440,
        "candidate_record_stride_bytes":64,
        "candidate_record_count":0x440//64,
        "evidence":[
          line_at(report["targets"],"pool_21c",0x227ec),
          line_at(report["targets"],"pool_21c",0x227f0),
          line_at(report["targets"],"pool_21c",0x227f8),
          line_at(report["targets"],"halfwords_2_6",0x2a244),
          line_at(report["targets"],"halfwords_2_6",0x2a248),
        ],
        "inference":"The field receives an allocation-like helper return for 1088 bytes. A later consumer loads +0x21c and indexes from it with a <<6 stride, supporting a 17 x 64-byte record-table shape candidate."
      },
    }
    report["guardrail"]="Writer PCs retained here are exact-anchor writes after the writeback provenance correction. Allocation-like interpretation is bounded by the proven call graph (0x24e0 -> 0x2254); domain-specific field names remain unassigned until additional binary/source correlation supports them."
    (out/"runtime-anchor-initializers.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "excluded_non_anchor_candidates":{k:{"effective_base":hex(v["effective_base"]),"writeback_pc":hex(v["writeback_pc"])} for k,v in EXCLUDED_NON_ANCHOR_CANDIDATES.items()},
      "field_semantics":report["field_semantics"],
      **{"literal_values":report["literal_values"]},
      **{name:{
        "writer":rec["writer"]["text"] if rec["writer"] else None,
        "calls":[{"pc":hex(c["pc"]),"target":hex(c["target"])} for c in rec["calls"]],
        "interesting_immediates":[hex(x["value"]) for x in rec["immediates"][:40]],
      } for name,rec in report["targets"].items()}
    },indent=2,sort_keys=True))
    return 0 if all(x["writer"] is not None for x in report["targets"].values()) else 3

if __name__=="__main__":raise SystemExit(main())
