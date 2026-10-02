#!/usr/bin/env python3
"""Instruction-level differential rehost of 88W8964 MEM_ADDR_ACCESS selector 0."""
from __future__ import annotations

import argparse
import importlib.util
import json
import struct
from pathlib import Path
from typing import Any

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R7, UC_ARM_REG_SP

SEM_PATH=Path(__file__).with_name("wrt3200acm_memaddr_semantics.py")
SPEC=importlib.util.spec_from_file_location("memaddr_sem",SEM_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load semantic model")
sem=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(sem)

START=0x37DE8
STOP=0x385AC
PAGE=0x1000
CMD_ADDR=0x10000000
CTRL_ADDR=0x10010000
STACK_ADDR=0x10020000
TARGET_ADDR=0x20000000

def align_up(x:int,a:int=PAGE)->int:
    return (x+a-1)&~(a-1)

def elf_load_segments(path:Path)->list[tuple[int,bytes]]:
    d=path.read_bytes()
    if d[:4]!=b"\x7fELF" or d[4]!=1 or d[5]!=1:
        raise ValueError("expected ELF32 little-endian")
    phoff=struct.unpack_from("<I",d,28)[0]
    phentsize=struct.unpack_from("<H",d,42)[0]
    phnum=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(phnum):
        off=phoff+i*phentsize
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,off)
        if typ==1 and fs:
            out.append((va,d[fo:fo+fs]))
    return out

def map_blob(uc:Uc,address:int,data:bytes):
    base=address&~(PAGE-1)
    prefix=address-base
    uc.mem_map(base,align_up(prefix+len(data)))
    uc.mem_write(address,data)

def run_case(elf:Path,count:int,words:list[int])->dict[str,Any]:
    if len(words)<min(count,64):
        raise ValueError("insufficient words")
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN)
    for va,blob in elf_load_segments(elf):
        # Only map segments needed as firmware code/data.
        map_blob(uc,va,blob)
    uc.mem_map(CMD_ADDR,PAGE)
    uc.mem_map(CTRL_ADDR,PAGE)
    uc.mem_map(STACK_ADDR,PAGE)
    uc.mem_map(TARGET_ADDR,PAGE)
    request=sem.make_request(TARGET_ADDR,count,selector=0,header_len=272)
    uc.mem_write(CMD_ADDR,request)
    for i,v in enumerate(words[:64]):
        uc.mem_write(TARGET_ADDR+4*i,struct.pack("<I",v&0xffffffff))
    # Proven precondition: skip optional call at 0x363e4.
    uc.mem_write(CTRL_ADDR+0x24,b"\x00\x00\x00\x00")
    uc.reg_write(UC_ARM_REG_R4,CMD_ADDR)
    uc.reg_write(UC_ARM_REG_R7,CTRL_ADDR)
    uc.reg_write(UC_ARM_REG_SP,STACK_ADDR+PAGE-0x100)

    stopped={"ok":False}
    target_reads=[]
    executed=[]
    def on_code(uc,address,size,user):
        if len(executed)<256:
            executed.append(address)
        if address==STOP:
            stopped["ok"]=True
            uc.emu_stop()
    def on_read(uc,access,address,size,value,user):
        if TARGET_ADDR<=address<TARGET_ADDR+PAGE:
            target_reads.append({"address":address,"size":size})
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.hook_add(UC_HOOK_MEM_READ,on_read)
    uc.emu_start(START,STOP+4,count=5000)
    response=bytes(uc.mem_read(CMD_ADDR,len(request)))

    read_map={TARGET_ADDR+4*i:words[i] for i in range(min(count,64))}
    model=sem.execute_selector0(request,lambda a:read_map[a]) if count<=64 else None
    comparable=(model==response) if model is not None else None
    values=[struct.unpack_from("<I",response,16+4*i)[0] for i in range(min(count,64))]
    return {
        "count":count,
        "reached_common_exit":stopped["ok"],
        "target_memory_reads":target_reads,
        "response_values":values,
        "semantic_model_byte_identical":comparable,
        "executed_prefix":[f"0x{x:08x}" for x in executed[:64]],
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    cases=[
        run_case(elf,3,[0x11223344,0xaabbccdd,0x01020304]),
        run_case(elf,0,[]),
        run_case(elf,65,[i for i in range(65)]),
    ]
    acceptance={
        "count3_machine_matches_semantic_model":cases[0]["semantic_model_byte_identical"] is True,
        "count3_reads_exact_three_dwords":[x["address"] for x in cases[0]["target_memory_reads"]]==[TARGET_ADDR,TARGET_ADDR+4,TARGET_ADDR+8],
        "count0_no_target_reads":cases[1]["target_memory_reads"]==[],
        "count65_rejected_before_target_read":cases[2]["target_memory_reads"]==[],
        "all_cases_reach_common_exit":all(c["reached_common_exit"] for c in cases),
    }
    report={
        "schema":"wrt8964-memaddr-unicorn-differential/v1",
        "engine":"Unicorn ARM instruction emulator",
        "handler_start":"0x00037de8",
        "stop_before_common_exit":"0x000385ac",
        "preconditions":["[r7+0x24] is zero so the optional 0x000363e4 pre-handler call is skipped"],
        "cases":cases,
        "acceptance":acceptance,
        "all_acceptance_pass":all(acceptance.values()),
        "guardrail":"This proves the selected straight-line selector-0 path under explicitly mapped memory. It does not emulate unknown radio peripherals or selector 1-3 helpers."
    }
    (out/"memaddr-unicorn-differential.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(acceptance,indent=2,sort_keys=True))
    return 0 if report["all_acceptance_pass"] else 3

if __name__=="__main__":
    raise SystemExit(main())
