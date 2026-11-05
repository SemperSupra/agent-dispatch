#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, re, subprocess
from pathlib import Path

RUNTIME_MARKERS=["ThreadX","FreeRTOS","VxWorks","Nucleus","tx_thread","tx_semaphore","pthread","malloc","memcpy","memset"]
CORPUS=r"""
#include <stdint.h>
uint32_t rd32(const volatile uint32_t *p){ return *p; }
void wr32(volatile uint32_t *p,uint32_t v){ *p=v; }
uint32_t fold(const uint8_t *p){ return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
int bounded(uint32_t n,const uint32_t *p,uint32_t *o){ if(n>64)return -1; for(uint32_t i=0;i<n;i++)o[i]=p[i]; return 0; }
"""

def run(cmd):
    return subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=120)

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--work",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    work=Path(ns.work); work.mkdir(parents=True,exist_ok=True); out=Path(ns.out); out.parent.mkdir(parents=True,exist_ok=True)
    src=work/"fingerprint.c"; src.write_text(CORPUS)
    builds=[]
    configs=[
      ("gcc-O2",["arm-linux-gnueabi-gcc","-mcpu=cortex-a9","-marm","-O2","-ffreestanding","-fno-builtin","-c",str(src),"-o",str(work/"gcc-O2.o")]),
      ("gcc-Os",["arm-linux-gnueabi-gcc","-mcpu=cortex-a9","-marm","-Os","-ffreestanding","-fno-builtin","-c",str(src),"-o",str(work/"gcc-Os.o")]),
      ("clang-O2",["clang","--target=arm-linux-gnueabi","-mcpu=cortex-a9","-marm","-O2","-ffreestanding","-fno-builtin","-c",str(src),"-o",str(work/"clang-O2.o")]),
    ]
    for name,cmd in configs:
        cp=run(cmd); rec={"name":name,"rc":cp.returncode,"stderr":cp.stderr[-3000:]}
        obj=work/(name+".o")
        if cp.returncode==0:
            od=run(["arm-linux-gnueabi-objdump","-d",str(obj)])
            rec["disassembly"]=od.stdout[-20000:]
        builds.append(rec)
    # Scan bounded firmware strings for runtime/RTOS markers.
    st=run(["strings","-a","-n","5",str(ns.elf)])
    markers={m:[line for line in st.stdout.splitlines() if m.lower() in line.lower()][:50] for m in RUNTIME_MARKERS}
    markers={k:v for k,v in markers.items() if v}
    # Interworking clues.
    od=run(["arm-linux-gnueabi-objdump","-D","-m","arm","-EL",str(ns.elf)])
    inter=[line for line in od.stdout.splitlines() if re.search(r"\b(blx|bx)\b",line)][:500]
    report={
      "schema":"wrt8964-toolchain-runtime-archaeology/v1",
      "known_target":{"cpu":"Cortex-A9","isa":"ARMv7-A","endianness":"little"},
      "compiler_smoke":builds,
      "runtime_string_markers":markers,
      "interworking_instruction_samples":inter,
      "conclusions":[
        "A reproducible free GCC/Clang Cortex-A9 ARM build environment is available if all compiler smoke builds succeed.",
        "Compiler identity and RTOS identity are not inferred from this smoke test alone."
      ]
    }
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    ok=sum(1 for x in builds if x["rc"]==0)
    print(json.dumps({"successful_compiler_configs":ok,"runtime_markers":list(markers),"interworking_samples":len(inter)},indent=2))
    return 0 if ok>=2 else 3
if __name__=="__main__": raise SystemExit(main())
