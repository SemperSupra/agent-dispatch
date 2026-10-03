#!/usr/bin/env python3
"""Find direct writes to fields of the 0x706c0 runtime context with local register provenance."""
from __future__ import annotations
import argparse, importlib.util, json, re, struct
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

ANCHOR=0x706c0
REG=r"(?:r(?:1[0-2]|[0-9])|sp|lr)"

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

def written_reg(mn:str,ops:str):
    if mn.startswith(("str","stm","cmp","cmn","tst","teq","b","push")): return None
    m=re.match(r"\s*("+REG+r")\b",ops)
    return m.group(1) if m else None

def writeback_bases(ops:str):
    """Return base registers modified by ARM pre/post-indexed addressing.

    Examples:
      ldr r4, [r1, r2]!  -> r1 no longer equals its pre-instruction value
      str r0, [r1], #4   -> r1 no longer equals its pre-instruction value
    """
    out=set()
    for m in re.finditer(r"\[\s*("+REG+r")\b[^\]]*\]\s*!",ops):
        out.add(m.group(1))
    for m in re.finditer(r"\[\s*("+REG+r")\s*\]\s*,",ops):
        out.add(m.group(1))
    # LDM/STM encode writeback as "rN!" rather than bracket syntax.
    m=re.match(r"\s*("+REG+r")!\s*,",ops)
    if m:
        out.add(m.group(1))
    return out

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    segs=elf_segments(elf)
    low_end=max(va+len(data) for va,data,_ in segs if va<0x1000000)
    slots=literal_slots(segs,ANCHOR)
    ins=dp.parse_instructions(dp.run_objdump(elf,0,low_end))
    loads=[]; writers=[]; readers=[]; provenance_kills=[]

    for i,x in enumerate(ins):
        if x["mnemonic"]!="ldr": continue
        m=re.search(r"^\s*("+REG+r")\s*,\s*\[pc[^\]]*\].*@\s*0x([0-9a-fA-F]+)",x["operands"])
        if not m: continue
        reg=m.group(1); slot=int(m.group(2),16)
        if slot not in slots: continue
        loads.append({"pc":x["address"],"reg":reg,"slot":slot,"text":x["text"]})
        tracked={reg}

        # Local, fail-closed propagation only. The tracked set means
        # "this register still contains exactly ANCHOR", not merely a value
        # derived from it.
        for y in ins[i+1:min(len(ins),i+81)]:
            mn=y["mnemonic"]; ops=y["operands"]
            if mn=="bx" or (mn=="pop" and "pc" in ops):
                break

            # Record memory accesses using the PRE-instruction provenance.
            for base in list(tracked):
                mm=re.search(r"\["+re.escape(base)+r"(?:, #([0-9]+))?\]",ops)
                if mm:
                    off=int(mm.group(1) or "0")
                    rec={"anchor_load_pc":x["address"],"pc":y["address"],"base_reg":base,"offset":off,"text":y["text"]}
                    if mn.startswith(("str","stm")): writers.append(rec)
                    elif mn.startswith(("ldr","ldm")): readers.append(rec)

            # Compute exact alias transfers from PRE-instruction state.
            new_aliases=set()
            mm=re.match(r"\s*("+REG+r")\s*,\s*("+REG+r")\s*$",ops)
            if mn=="mov" and mm and mm.group(2) in tracked:
                new_aliases.add(mm.group(1))
            mm=re.match(r"\s*("+REG+r")\s*,\s*("+REG+r")\s*,\s*#0\s*$",ops)
            if mn in {"add","sub"} and mm and mm.group(2) in tracked:
                new_aliases.add(mm.group(1))

            # Any ordinary destination write kills the old exact-anchor fact.
            wr=written_reg(mn,ops)
            if wr is not None:
                tracked.discard(wr)

            # Pre/post-indexed addressing mutates the base register itself.
            # This was the v2 provenance hole: e.g. [r1, r2]! changed r1 from
            # ANCHOR to ANCHOR+r2, yet later [r1] stores were mislabeled offset 0.
            for wb in writeback_bases(ops):
                if wb in tracked:
                    provenance_kills.append({
                        "anchor_load_pc":x["address"],
                        "pc":y["address"],
                        "base_reg":wb,
                        "reason":"address_writeback",
                        "text":y["text"],
                    })
                tracked.discard(wb)

            tracked.update(new_aliases)

            # Calls clobber caller-saved registers.
            if mn=="bl":
                tracked={r for r in tracked if r in {"r4","r5","r6","r7","r8","r9","r10","r11"}}
            if mn=="b":
                break

    def uniq(xs):
        seen=set(); out=[]
        for rec in xs:
            k=(rec["anchor_load_pc"],rec["pc"],rec.get("offset"),rec["text"],rec.get("reason"))
            if k not in seen: seen.add(k); out.append(rec)
        return out
    writers=uniq(writers); readers=uniq(readers); provenance_kills=uniq(provenance_kills)
    by_offset={}
    for rec in writers: by_offset.setdefault(rec["offset"],[]).append(rec)

    historical={
      "0x2d3c8":any(r["pc"]==0x2d3c8 for r in writers),
      "0x30808":any(r["pc"]==0x30808 for r in writers),
    }
    report={
      "schema":"wrt8964-runtime-anchor-direct-writers/v3",
      "anchor":ANCHOR,
      "literal_slots":sorted(slots),
      "anchor_loads":loads,
      "direct_writers":writers,
      "direct_readers":readers,
      "provenance_kills":provenance_kills,
      "writers_by_offset":{str(k):v for k,v in sorted(by_offset.items())},
      "offset0_writers":by_offset.get(0,[]),
      "historical_false_positive_candidates":historical,
      "guardrail":"Only registers still proven equal to the exact anchor are accepted as bases. Destination overwrites and pre/post-indexed address writeback kill provenance before new exact aliases are added. Calls clobber caller-saved aliases; unconditional branches/returns terminate propagation. Absence of a writer does not prove immutability."
    }
    (out/"runtime-anchor-direct-writers.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "anchor_load_count":len(loads),
      "writer_count":len(writers),
      "writer_offsets":[hex(x) for x in sorted(by_offset)],
      "offset0_writers":[{"load_pc":hex(x["anchor_load_pc"]),"pc":hex(x["pc"]),"text":x["text"]} for x in by_offset.get(0,[])],
      "known_crypto_offsets":{hex(k):[hex(x["pc"]) for x in v] for k,v in by_offset.items() if k in {0,2,4,6,0x4c,0xd8,0x208,0x214,0x21c}},
      "historical_false_positive_candidates":historical,
      "writeback_kills":[{"load_pc":hex(x["anchor_load_pc"]),"pc":hex(x["pc"]),"base_reg":x["base_reg"],"text":x["text"]} for x in provenance_kills],
    },indent=2,sort_keys=True))
    return 0 if not any(historical.values()) else 3

if __name__=="__main__": raise SystemExit(main())
