#!/usr/bin/env python3
"""Find initialization/use sites for the runtime RAM window returned by MEM_ADDR_ACCESS selector 3."""
from __future__ import annotations
import argparse, importlib.util, json, re, struct
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P); dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

LOW=0x706c0
HIGH=0x72ff8
SPAN=HIGH-LOW

def elf_segments(path:Path):
    d=path.read_bytes()
    phoff=struct.unpack_from("<I",d,28)[0]; ent=struct.unpack_from("<H",d,42)[0]; n=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(n):
        o=phoff+i*ent
        typ,fo,va,_pa,fs,ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs:
            out.append((va,d[fo:fo+fs],ms))
    return out

def literal_slots(segs,value:int):
    needle=struct.pack("<I",value); out=[]
    for va,data,_ms in segs:
        p=0
        while True:
            i=data.find(needle,p)
            if i<0:break
            out.append(va+i); p=i+1
    return out

def parse_refs(disasm:str,slots:set[int]):
    out=[]
    for line in disasm.splitlines():
        maddr=re.match(r"^\s*([0-9a-fA-F]+):",line)
        if not maddr: continue
        pc=int(maddr.group(1),16)
        m=re.search(r"@\s*0x([0-9a-fA-F]+)\b",line)
        if not m: continue
        slot=int(m.group(1),16)
        if slot in slots:
            out.append({"pc":pc,"slot":slot,"line":line.strip()})
    return out

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    segs=elf_segments(elf)
    low_slots=set(literal_slots(segs,LOW)); high_slots=set(literal_slots(segs,HIGH))
    low_end=max(va+len(data) for va,data,_ in segs if va<0x1000000)
    dis=dp.run_objdump(elf,0,low_end)
    low_refs=parse_refs(dis,low_slots); high_refs=parse_refs(dis,high_slots)

    # Nearby references to both endpoints are candidate range-management/init sites.
    pairs=[]
    for l in low_refs:
        for h in high_refs:
            dist=abs(l["pc"]-h["pc"])
            if dist<=0x180:
                a=max(0,min(l["pc"],h["pc"])-0x80)
                b=max(l["pc"],h["pc"])+0x100
                window=dp.run_objdump(elf,a,b)
                calls=[]
                for ins in dp.parse_instructions(window):
                    if ins["mnemonic"]=="bl":
                        t=dp.branch_target(ins)
                        if t is not None:calls.append(t)
                # crude evidence-bearing zero/copy idioms only; labels are not assigned.
                zeroish=bool(re.search(r"\bmov\w*\s+r\d+, #0\b",window))
                stores=bool(re.search(r"\bstr\w*\b",window))
                pairs.append({
                    "low_ref":l,"high_ref":h,"distance":dist,
                    "window_start":a,"window_end":b,
                    "direct_call_targets":sorted(set(calls)),
                    "contains_zero_immediate":zeroish,
                    "contains_store":stores,
                    "window":window,
                })
    # Deduplicate by window/ref PCs.
    uniq=[]; seen=set()
    for p in sorted(pairs,key=lambda x:(x["distance"],x["low_ref"]["pc"],x["high_ref"]["pc"])):
        k=(p["low_ref"]["pc"],p["high_ref"]["pc"])
        if k not in seen:
            seen.add(k); uniq.append(p)

    # Also inspect known nearby use of LOW from the encryption enable helper.
    focused={}
    for name,(a,b) in {
        "enable_helper_prequel":(0x28ed0,0x28f54),
        "set_key_first_fault_pc":(0x29104,0x29170),
        "shared_remove_fault_pc":(0x3fb40,0x3fbc0),
    }.items():
        focused[name]=dp.run_objdump(elf,a,b)
        (out/f"{name}.txt").write_text(focused[name])

    report={
      "schema":"wrt8964-runtime-window-init-search/v1",
      "window":{"low":LOW,"high":HIGH,"span":SPAN},
      "loaded_low_image_end":low_end,
      "literal_slots":{"low":sorted(low_slots),"high":sorted(high_slots)},
      "reference_counts":{"low":len(low_refs),"high":len(high_refs)},
      "low_refs":low_refs,"high_refs":high_refs,
      "nearby_endpoint_ref_pairs":[{k:v for k,v in p.items() if k!="window"} for p in uniq],
      "focused_disassembly_files":list(focused),
      "classification":{
        "observed":"The two selector-3 endpoint constants are referenced broadly by executable firmware; nearby dual-endpoint references identify candidate range-management or initialization sites.",
        "guardrail":"A nearby low/high reference pair is not sufficient to call the region BSS, heap, or zero-initialized. Initialization semantics require an observed store/clear/copy path and source/dynamic corroboration."
      }
    }
    (out/"runtime-window-init-search.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    for i,p in enumerate(uniq[:24]):
        (out/f"candidate-pair-{i:02d}.txt").write_text(p["window"])
    print(json.dumps({
      "window":[hex(LOW),hex(HIGH),hex(SPAN)],
      "low_ref_count":len(low_refs),"high_ref_count":len(high_refs),
      "candidate_pair_count":len(uniq),
      "top_pairs":[{
        "low_pc":hex(p["low_ref"]["pc"]),"high_pc":hex(p["high_ref"]["pc"]),
        "distance":hex(p["distance"]),
        "calls":[hex(x) for x in p["direct_call_targets"]],
        "zero_immediate":p["contains_zero_immediate"],"store":p["contains_store"]
      } for p in uniq[:16]]
    },indent=2,sort_keys=True))
    return 0

if __name__=="__main__":raise SystemExit(main())
