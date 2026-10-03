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
    m=re.match(r"\s*(r(?:1[0-2]|[0-9])|sp|lr)\b",ops)
    return m.group(1) if m else None

def mem_uses(ops):
    return [(m.group(1),int(m.group(2) or "0")) for m in re.finditer(r"\[(r(?:1[0-2]|[0-9])|sp|lr)(?:, #([0-9]+))?\]",ops)]

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    segs=segments(elf);low_end=max(va+len(d) for va,d,_ in segs if va<0x1000000)
    slotsets={k:slots(segs,v) for k,v in ANCHORS.items()}
    ins=dp.parse_instructions(dp.run_objdump(elf,0,low_end))
    reg_anchor={}
    accesses=[]
    anchor_loads=[]
    for x in ins:
        mn=x["mnemonic"];ops=x["operands"];pc=x["address"]
        # Snapshot anchor identities before destination invalidation.
        prior=dict(reg_anchor)
        # Record memory accesses through anchored registers.
        for base,off in mem_uses(ops):
            if base in prior:
                kind="write" if mn.startswith(("str","stm")) else "read" if mn.startswith(("ldr","ldm")) else "other"
                accesses.append({
                  "pc":pc,"anchor":prior[base],"base_reg":base,"offset":off,
                  "absolute":ANCHORS[prior[base]]+off,"kind":kind,"mnemonic":mn,"text":x["text"]
                })
        dreg=dest_reg(mn,ops)
        if dreg is not None:
            reg_anchor.pop(dreg,None)
        # PC-relative literal load of an anchor.
        m=re.search(r"^\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*\[pc[^\]]*\].*@\s*0x([0-9a-fA-F]+)",ops)
        if mn=="ldr" and m:
            reg=m.group(1);slot=int(m.group(2),16)
            for name,ss in slotsets.items():
                if slot in ss:
                    reg_anchor[reg]=name
                    anchor_loads.append({"pc":pc,"reg":reg,"anchor":name,"slot":slot,"text":x["text"]})
        # Simple anchor-preserving copies.
        m=re.match(r"\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*$",ops)
        if mn=="mov" and m and m.group(2) in prior:
            reg_anchor[m.group(1)]=prior[m.group(2)]
        m=re.match(r"\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*(r(?:1[0-2]|[0-9])|sp|lr)\s*,\s*#0\s*$",ops)
        if mn=="add" and m and m.group(2) in prior:
            reg_anchor[m.group(1)]=prior[m.group(2)]
        # Returns/large control transfers make linear register facts unsafe.
        if mn in {"bx","pop"} and ("pc" in ops or "lr" in ops):
            reg_anchor.clear()

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
    report={
      "schema":"wrt8964-selector3-anchor-field-map/v1",
      "anchors":ANCHORS,
      "literal_slots":{k:sorted(v) for k,v in slotsets.items()},
      "by_anchor":by_anchor,
      "all_accesses":accesses,
      "classification":{
        "observed":"Firmware repeatedly loads both selector-3 values as absolute bases and dereferences fields at fixed offsets. UPDATE_ENCRYPTION first missing accesses are low-anchor fields +0x6, +0x4c, and +0x21c.",
        "correction":"Treat selector-3 values as runtime global/state anchors unless and until explicit bound semantics are independently shown; do not assume they are low/high bounds of one contiguous arena."
      }
    }
    (out/"selector3-anchor-field-map.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      k:{
        "load_sites":len(v["load_sites"]),"access_count":v["access_count"],
        "read_offsets":[hex(x) for x in v["read_offsets"][:80]],
        "write_offsets":[hex(x) for x in v["write_offsets"][:80]],
        "focus":[{"pc":hex(a["pc"]),"offset":hex(a["offset"]),"kind":a["kind"],"text":a["text"]} for a in v["focus_accesses"][:80]]
      } for k,v in by_anchor.items()
    },indent=2,sort_keys=True))
    return 0
if __name__=="__main__":raise SystemExit(main())
