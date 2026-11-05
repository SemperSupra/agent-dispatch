#!/usr/bin/env python3
"""Correlate UPDATE_ENCRYPTION's first missing runtime state with MEM_ADDR selector-3 literals."""
from __future__ import annotations
import argparse, importlib.util, json, re, struct
from pathlib import Path

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P); dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

REGION_LO=0x706c0
REGION_HI=0x72ff8
FAULTS={
 "set_key_first_missing":(0x706c6,0x29134,2),
 "remove_first_missing":(0x7070c,0x3fb78,4),
 "enable_first_missing":(0x708dc,0x28f68,4),
}
LITERALS={"selector3_high":REGION_HI,"selector3_low":REGION_LO}

def elf_segments(path:Path):
    d=path.read_bytes();phoff=struct.unpack_from("<I",d,28)[0];ent=struct.unpack_from("<H",d,42)[0];n=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(n):
        o=phoff+i*ent
        typ,fo,va,_pa,fs,ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and fs:out.append({"file_off":fo,"vaddr":va,"filesz":fs,"memsz":ms,"data":d[fo:fo+fs]})
    return out

def occurrences(segs,value:int):
    needle=struct.pack("<I",value); out=[]
    for seg in segs:
        start=0
        while True:
            i=seg["data"].find(needle,start)
            if i<0:break
            out.append(seg["vaddr"]+i);start=i+1
    return out

def xrefs(disasm:str,slots:list[int]):
    out=[]
    for line in disasm.splitlines():
        low=line.lower()
        for slot in slots:
            # GNU objdump PC-relative literal comments usually print "@ 0x..."
            if re.search(r"@\s*0x0*"+format(slot,"x")+r"\b",low):
                out.append({"literal_slot":slot,"line":line.strip()})
    return out

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    segs=elf_segments(elf)
    first_end=max((s["vaddr"]+s["filesz"] for s in segs if s["vaddr"]<0x1000000),default=0)
    literal_slots={k:occurrences(segs,v) for k,v in LITERALS.items()}
    whole=dp.run_objdump(elf,0,first_end)
    refmap={k:xrefs(whole,v) for k,v in literal_slots.items()}
    windows={}
    for name,(addr,pc,size) in FAULTS.items():
        windows[name]={
          "fault_address":addr,"fault_offset_from_selector3_low":addr-REGION_LO,
          "inside_selector3_window":REGION_LO<=addr<REGION_HI,
          "access_pc":pc,"access_size":size,
          "pc_window":dp.run_objdump(elf,max(0,pc-0x30),pc+0x40)
        }
    report={
      "schema":"wrt8964-crypto-runtime-state-region/v1",
      "loaded_low_image_end":first_end,
      "selector3_literals":{"value0_high":REGION_HI,"value2_low":REGION_LO,"span_bytes":REGION_HI-REGION_LO},
      "deep_rehost_first_missing":windows,
      "all_faults_inside_selector3_window":all(v["inside_selector3_window"] for v in windows.values()),
      "literal_slots":literal_slots,
      "literal_xrefs":refmap,
      "classification":{
        "observed":"All three UPDATE_ENCRYPTION first-unmapped accesses lie inside the low-address window bounded by the two MEM_ADDR_ACCESS selector-3 literals.",
        "inference":"This strongly suggests selector 3 exposes bounds or anchors for firmware runtime RAM/state used by encryption helpers.",
        "not_yet_proven":"The window is not yet proven to be zero-initialized BSS, heap, or a specific named subsystem; no contents are invented."
      }
    }
    (out/"crypto-runtime-state-region.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    for k,v in windows.items():(out/f"{k}-pc-window.txt").write_text(v["pc_window"])
    print(json.dumps({
      "loaded_low_image_end":hex(first_end),
      "selector3_window":[hex(REGION_LO),hex(REGION_HI)],
      "faults":{k:{"addr":hex(v["fault_address"]),"delta":hex(v["fault_offset_from_selector3_low"]),"inside":v["inside_selector3_window"]} for k,v in windows.items()},
      "all_faults_inside_selector3_window":report["all_faults_inside_selector3_window"],
      "literal_slots":{k:[hex(x) for x in v] for k,v in literal_slots.items()},
      "xref_counts":{k:len(v) for k,v in refmap.items()}
    },indent=2,sort_keys=True))
    return 0 if report["all_faults_inside_selector3_window"] else 3

if __name__=="__main__":raise SystemExit(main())
