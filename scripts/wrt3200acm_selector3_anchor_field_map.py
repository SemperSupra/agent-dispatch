#!/usr/bin/env python3
"""Map fields accessed through the two runtime anchors returned by MEM_ADDR_ACCESS selector 3."""
from __future__ import annotations
import argparse, importlib.util, json, re, struct
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P); dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

ANCHORS={"low":0x706c0,"high":0x72ff8}
FOCUS_OFFSETS={
  "low":{0x0,0x2,0x4,0x6,0x4c,0xd8,0x208,0x214,0x21c},
  "high":set(),
}
REG=r"(?:r(?:1[0-2]|[0-9])|sp|lr)"

def segments(path:Path):
    d=path.read_bytes();ph=struct.unpack_from("<I",d,28)[0];pe=struct.unpack_from("<H",d,42)[0];pn=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(pn):
        o=ph+i*pe;typ,fo,va,_pa,fs,ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs:out.append((va,d[fo:fo+fs],ms))
    return out

def slots(segs,value):
    n=struct.pack("<I",value);out=set()
    for va,d,_ in segs:
        p=0
        while True:
            i=d.find(n,p)
            if i<0:break
            out.add(va+i);p=i+1
    return out

def dest_reg(mn,ops):
    # ARM data/load instructions usually write their first register operand.
    if mn.startswith(("str","stm","cmp","cmn","tst","teq","b","push")):return None
    m=re.match(r"\s*("+REG+r")\b",ops)
    return m.group(1) if m else None

def mem_uses(ops):
    return [(m.group(1),int(m.group(2) or "0")) for m in re.finditer(r"\[("+REG+r")(?:, #([0-9]+))?\]",ops)]

def writeback_bases(ops):
    """Registers whose values are changed by ARM pre/post-indexed addressing."""
    out=set()
    for m in re.finditer(r"\[\s*("+REG+r")\b[^\]]*\]\s*!",ops):
        out.add(m.group(1))
    for m in re.finditer(r"\[\s*("+REG+r")\s*\]\s*,",ops):
        out.add(m.group(1))
    m=re.match(r"\s*("+REG+r")!\s*,",ops)
    if m:out.add(m.group(1))
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    segs=segments(elf);low_end=max(va+len(d) for va,d,_ in segs if va<0x1000000)
    slotsets={k:slots(segs,v) for k,v in ANCHORS.items()}
    ins=dp.parse_instructions(dp.run_objdump(elf,0,low_end))
    reg_anchor={}
    accesses=[]
    anchor_loads=[]
    provenance_kills=[]
    for x in ins:
        mn=x["mnemonic"];ops=x["operands"];pc=x["address"]
        # Snapshot exact-anchor identities before this instruction mutates registers.
        prior=dict(reg_anchor)

        # Record memory accesses through exact anchored registers using PRE-instruction state.
        for base,off in mem_uses(ops):
            if base in prior:
                kind="write" if mn.startswith(("str","stm")) else "read" if mn.startswith(("ldr","ldm")) else "other"
                accesses.append({
                  "pc":pc,"anchor":prior[base],"base_reg":base,"offset":off,
                  "absolute":ANCHORS[prior[base]]+off,"kind":kind,"mnemonic":mn,"text":x["text"]
                })

        # Ordinary destination writes kill the previous exact-anchor identity.
        dreg=dest_reg(mn,ops)
        if dreg is not None:
            reg_anchor.pop(dreg,None)

        # Pre/post-indexed addressing mutates the base register itself.  This is
        # the provenance hole that previously misclassified 0x2d3c8 and
        # 0x30808 as low-anchor offset-0 writers after [r1, r2]! updates.
        for base in writeback_bases(ops):
            if base in prior:
                provenance_kills.append({
                  "pc":pc,"base_reg":base,"anchor":prior[base],
                  "reason":"address_writeback","text":x["text"]
                })
            reg_anchor.pop(base,None)

        # PC-relative literal load of an anchor.
        m=re.search(r"^\s*("+REG+r")\s*,\s*\[pc[^\]]*\].*@\s*0x([0-9a-fA-F]+)",ops)
        if mn=="ldr" and m:
            reg=m.group(1);slot=int(m.group(2),16)
            for name,ss in slotsets.items():
                if slot in ss:
                    reg_anchor[reg]=name
                    anchor_loads.append({"pc":pc,"reg":reg,"anchor":name,"slot":slot,"text":x["text"]})

        # Simple exact-anchor-preserving copies from PRE-instruction state.
        m=re.match(r"\s*("+REG+r")\s*,\s*("+REG+r")\s*$",ops)
        if mn=="mov" and m and m.group(2) in prior:
            reg_anchor[m.group(1)]=prior[m.group(2)]
        m=re.match(r"\s*("+REG+r")\s*,\s*("+REG+r")\s*,\s*#0\s*$",ops)
        if mn in {"add","sub"} and m and m.group(2) in prior:
            reg_anchor[m.group(1)]=prior[m.group(2)]

        # Calls destroy caller-saved identities.  Unconditional branches and
        # returns end this linear fact stream; do not carry register facts into
        # unrelated basic blocks.
        if mn=="bl":
            reg_anchor={r:a for r,a in reg_anchor.items() if r in {"r4","r5","r6","r7","r8","r9","r10","r11"}}
        if mn=="b" or mn=="bx" or (mn=="pop" and "pc" in ops):
            reg_anchor.clear()

    def uniq(xs):
        seen=set(); out=[]
        for rec in xs:
            k=tuple(sorted(rec.items()))
            if k not in seen:seen.add(k);out.append(rec)
        return out
    accesses=uniq(accesses); provenance_kills=uniq(provenance_kills)

    by_anchor={}
    for name in ANCHORS:
        aa=[a for a in accesses if a["anchor"]==name]
        by_anchor[name]={
          "load_sites":[x for x in anchor_loads if x["anchor"]==name],
          "access_count":len(aa),
          "read_offsets":sorted({a["offset"] for a in aa if a["kind"]=="read"}),
          "write_offsets":sorted({a["offset"] for a in aa if a["kind"]=="write"}),
          "focus_accesses":[a for a in aa if a["offset"] in FOCUS_OFFSETS[name]],
        }
    historical={
      "0x2d3c8":any(a["pc"]==0x2d3c8 and a["anchor"]=="low" and a["kind"]=="write" for a in accesses),
      "0x30808":any(a["pc"]==0x30808 and a["anchor"]=="low" and a["kind"]=="write" for a in accesses),
    }
    report={
      "schema":"wrt8964-selector3-anchor-field-map/v2",
      "anchors":ANCHORS,
      "literal_slots":{k:sorted(v) for k,v in slotsets.items()},
      "by_anchor":by_anchor,
      "all_accesses":accesses,
      "provenance_kills":provenance_kills,
      "historical_false_positive_candidates":historical,
      "guardrail":"Anchor field accesses require a register still proven equal to the exact anchor. Ordinary destination writes, address writeback, caller-saved clobbers, unconditional branches, and returns terminate the relevant register fact.",
      "classification":{
        "observed":"Firmware repeatedly loads both selector-3 values as absolute bases and dereferences fields at fixed offsets. UPDATE_ENCRYPTION first missing accesses include low-anchor fields +0x6, +0x4c, and +0x21c.",
        "correction":"Treat selector-3 values as runtime global/state anchors unless and until explicit bound semantics are independently shown; do not assume they are low/high bounds of one contiguous arena."
      }
    }
    (out/"selector3-anchor-field-map.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "historical_false_positive_candidates":historical,
      "provenance_kill_count":len(provenance_kills),
      "writeback_kills":[{"pc":hex(x["pc"]),"base_reg":x["base_reg"],"anchor":x["anchor"],"text":x["text"]} for x in provenance_kills if x["reason"]=="address_writeback"],
      **{k:{
        "load_sites":len(v["load_sites"]),"access_count":v["access_count"],
        "read_offsets":[hex(x) for x in v["read_offsets"][:80]],
        "write_offsets":[hex(x) for x in v["write_offsets"][:80]],
        "focus":[{"pc":hex(a["pc"]),"offset":hex(a["offset"]),"kind":a["kind"],"text":a["text"]} for a in v["focus_accesses"][:80]]
      } for k,v in by_anchor.items()}
    },indent=2,sort_keys=True))
    return 0 if not any(historical.values()) else 3
if __name__=="__main__":raise SystemExit(main())
