#!/usr/bin/env python3
"""Find direct writes to fields of the 0x706c0 runtime context with local register provenance."""
from __future__ import annotations
import argparse, importlib.util, json, re, struct
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

ANCHOR=0x706c0

def elf_segments(path:Path):
    d=path.read_bytes()
    ph=struct.unpack_from("<I",d,28)[0]; pe=struct.unpack_from("<H",d,42)[0]; pn=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(pn):
        o=ph+i*pe
        typ,fo,va,_pa,fs,ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs: out.append((va,d[fo:fo+fs],ms))
    return out

def literal_slots(segs,value):
    needle=struct.pack("<I",value); out=set()
    for va,data,_ in segs:
        p=0
        while True:
            i=data.find(needle,p)
            if i<0: break
            out.add(va+i); p=i+1
    return out

def regs_written(mn:str,ops:str):
    if mn.startswith(("str","stm","cmp","cmn","tst","teq","b","push")): return set()
    m=re.match(r"\s*(r(?:1[0-2]|[0-9])|sp|lr)\b",ops)
    return {m.group(1)} if m else set()

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    segs=elf_segments(elf)
    low_end=max(va+len(data) for va,data,_ in segs if va<0x1000000)
    slots=literal_slots(segs,ANCHOR)
    ins=dp.parse_instructions(dp.run_objdump(elf,0,low_end))
    index_by_addr={x["address"]:i for i,x in enumerate(ins)}
    loads=[]
    writers=[]
    readers=[]

    for i,x in enumerate(ins):
        if x["mnemonic"]!="ldr": continue
        m=re.search(r"^\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*\[pc[^\]]*\].*@\s*0x([0-9a-fA-F]+)",x["operands"])
        if not m: continue
        reg=m.group(1); slot=int(m.group(2),16)
        if slot not in slots: continue
        loads.append({"pc":x["address"],"reg":reg,"slot":slot,"text":x["text"]})
        tracked={reg}
        # Local, fail-closed propagation only. Stop at direct return or unconditional branch.
        for y in ins[i+1:min(len(ins),i+81)]:
            mn=y["mnemonic"]; ops=y["operands"]
            if mn in {"bx"} or (mn=="pop" and "pc" in ops):
                break
            # record memory references through any proven alias
            for t in list(tracked):
                mm=re.search(r"\["+re.escape(t)+r"(?:, #([0-9]+))?\]",ops)
                if mm:
                    off=int(mm.group(1) or "0")
                    rec={"anchor_load_pc":x["address"],"pc":y["address"],"base_reg":t,"offset":off,"text":y["text"]}
                    if mn.startswith(("str","stm")): writers.append(rec)
                    elif mn.startswith(("ldr","ldm")): readers.append(rec)
            # exact MOV alias
            mm=re.match(r"\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*$",ops)
            if mn=="mov" and mm and mm.group(2) in tracked:
                tracked.add(mm.group(1))
            # exact ADD alias by zero
            mm=re.match(r"\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*#0\s*$",ops)
            if mn=="add" and mm and mm.group(2) in tracked:
                tracked.add(mm.group(1))
            # calls clobber r0-r3/r12/lr; preserve callee-saved aliases only
            if mn=="bl":
                tracked={r for r in tracked if r in {"r4","r5","r6","r7","r8","r9","r10","r11"}}
            else:
                for w in regs_written(mn,ops):
                    # Preserve destination if it was just established as an alias above.
                    if not (mn in {"mov","add"} and w in tracked):
                        tracked.discard(w)
            if mn=="b":
                break

    # De-duplicate exact records.
    def uniq(xs):
        seen=set(); out=[]
        for x in xs:
            k=(x["anchor_load_pc"],x["pc"],x["offset"],x["text"])
            if k not in seen: seen.add(k); out.append(x)
        return out
    writers=uniq(writers); readers=uniq(readers)
    by_offset={}
    for rec in writers:
        by_offset.setdefault(rec["offset"],[]).append(rec)
    report={
      "schema":"wrt8964-runtime-anchor-direct-writers/v1",
      "anchor":ANCHOR,
      "literal_slots":sorted(slots),
      "anchor_loads":loads,
      "direct_writers":writers,
      "direct_readers":readers,
      "writers_by_offset":{str(k):v for k,v in sorted(by_offset.items())},
      "offset0_writers":by_offset.get(0,[]),
      "guardrail":"Only local aliases derived directly from an anchor literal load are tracked. Calls clobber caller-saved aliases; unconditional branches/returns terminate propagation. Absence of a writer does not prove immutability."
    }
    (out/"runtime-anchor-direct-writers.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "anchor_load_count":len(loads),
      "writer_count":len(writers),
      "writer_offsets":[hex(x) for x in sorted(by_offset)],
      "offset0_writers":[{"load_pc":hex(x["anchor_load_pc"]),"pc":hex(x["pc"]),"text":x["text"]} for x in by_offset.get(0,[])],
      "known_crypto_offsets":{hex(k):[hex(x["pc"]) for x in v] for k,v in by_offset.items() if k in {0,2,4,6,0x4c,0xd8,0x208,0x214,0x21c}}
    },indent=2,sort_keys=True))
    return 0

if __name__=="__main__": raise SystemExit(main())
