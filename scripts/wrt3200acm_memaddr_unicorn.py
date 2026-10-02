#!/usr/bin/env python3
"""Instruction-level differential rehost of all recovered 88W8964 MEM_ADDR_ACCESS selectors."""
from __future__ import annotations

import argparse
import importlib.util
import json
import struct
from pathlib import Path
from typing import Any

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
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

def align_up(x:int,a:int=PAGE)->int: return (x+a-1)&~(a-1)

def elf_load_segments(path:Path)->list[tuple[int,bytes]]:
    d=path.read_bytes()
    phoff=struct.unpack_from("<I",d,28)[0]; phentsize=struct.unpack_from("<H",d,42)[0]; phnum=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(phnum):
        off=phoff+i*phentsize
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,off)
        if typ==1 and fs: out.append((va,d[fo:fo+fs]))
    return out

def map_blob(uc:Uc,address:int,data:bytes):
    base=address&~(PAGE-1); prefix=address-base
    uc.mem_map(base,align_up(prefix+len(data))); uc.mem_write(address,data)

def make_uc(elf:Path)->Uc:
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN)
    for va,blob in elf_load_segments(elf): map_blob(uc,va,blob)
    uc.mem_map(CMD_ADDR,PAGE); uc.mem_map(CTRL_ADDR,PAGE); uc.mem_map(STACK_ADDR,PAGE); uc.mem_map(TARGET_ADDR,PAGE)
    uc.mem_write(CTRL_ADDR+0x24,b"\x00\x00\x00\x00")
    uc.reg_write(UC_ARM_REG_R7,CTRL_ADDR); uc.reg_write(UC_ARM_REG_SP,STACK_ADDR+PAGE-0x100)
    return uc

def execute_machine(elf:Path,request:bytes,target_seed:bytes)->dict[str,Any]:
    uc=make_uc(elf)
    uc.mem_write(CMD_ADDR,request)
    if target_seed: uc.mem_write(TARGET_ADDR,target_seed)
    uc.reg_write(UC_ARM_REG_R4,CMD_ADDR)
    stopped={"ok":False}; reads=[]; writes=[]
    def code(uc,address,size,user):
        if address==STOP: stopped["ok"]=True; uc.emu_stop()
    def rd(uc,access,address,size,value,user):
        if TARGET_ADDR<=address<TARGET_ADDR+PAGE: reads.append({"address":address,"size":size})
    def wr(uc,access,address,size,value,user):
        if TARGET_ADDR<=address<TARGET_ADDR+PAGE: writes.append({"address":address,"size":size,"value":value})
    uc.hook_add(UC_HOOK_CODE,code); uc.hook_add(UC_HOOK_MEM_READ,rd); uc.hook_add(UC_HOOK_MEM_WRITE,wr)
    uc.emu_start(START,STOP+4,count=10000)
    return {
        "response":bytes(uc.mem_read(CMD_ADDR,len(request))),
        "target":bytes(uc.mem_read(TARGET_ADDR,max(256,len(target_seed),4))),
        "reads":reads,"writes":writes,"reached_common_exit":stopped["ok"],
    }

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    selector3=(sem.read_elf_load_u32(elf,0x383a8),sem.read_elf_load_u32(elf,0x38384))
    cases=[]

    words=[0x11223344,0xaabbccdd,0x01020304]
    seed=b"".join(struct.pack("<I",x) for x in words)+b"\x00"*(256-12)
    req=sem.make_request(TARGET_ADDR,3,0)
    m=execute_machine(elf,req,seed)
    model=sem.execute(req,read32=lambda a:struct.unpack_from("<I",seed,a-TARGET_ADDR)[0])
    cases.append({"selector":0,"machine_response_matches_model":m["response"]==model,"machine":{k:v for k,v in m.items() if k!="response" and k!="target"}})

    req=sem.make_request(TARGET_ADDR,1,1,value0=0xdecafbad)
    m=execute_machine(elf,req,b"\x00"*256)
    model_mem={"value":0}
    model=sem.execute(req,write32=lambda a,v:model_mem.update(value=v))
    cases.append({"selector":1,"machine_response_matches_model":m["response"]==model,"machine_written_value":struct.unpack_from("<I",m["target"],0)[0],"model_written_value":model_mem["value"],"machine":{k:v for k,v in m.items() if k!="response" and k!="target"}})

    seed=bytes((i*37+11)&0xff for i in range(256))
    req=sem.make_request(TARGET_ADDR,0,2)
    m=execute_machine(elf,req,seed)
    model=sem.execute(req,read_block=lambda a,n:seed[:n])
    cases.append({"selector":2,"machine_response_matches_model":m["response"]==model,"response_block_matches_source":m["response"][16:272]==seed,"machine":{k:v for k,v in m.items() if k!="response" and k!="target"}})

    req=sem.make_request(TARGET_ADDR,0,3)
    m=execute_machine(elf,req,b"\x00"*256)
    model=sem.execute(req,selector3_values=selector3)
    cases.append({"selector":3,"machine_response_matches_model":m["response"]==model,"value0":f"0x{struct.unpack_from('<I',m['response'],16)[0]:08x}","value2":f"0x{struct.unpack_from('<I',m['response'],24)[0]:08x}","machine":{k:v for k,v in m.items() if k!="response" and k!="target"}})

    acceptance={
        "all_selectors_match_semantic_model":all(c["machine_response_matches_model"] for c in cases),
        "selector1_writes_exact_value":cases[1]["machine_written_value"]==0xdecafbad==cases[1]["model_written_value"],
        "selector2_returns_exact_256_byte_block":cases[2]["response_block_matches_source"],
        "all_selectors_reach_common_exit":all(c["machine"]["reached_common_exit"] for c in cases),
    }
    report={
        "schema":"wrt8964-memaddr-unicorn-differential/v2","engine":"Unicorn 2.1.4 ARM",
        "preconditions":["[r7+0x24]=0 skips optional pre-handler 0x000363e4"],
        "selector3_literals":[f"0x{x:08x}" for x in selector3],
        "cases":cases,"acceptance":acceptance,"all_acceptance_pass":all(acceptance.values()),
        "guardrail":"This validates only the recovered selector paths before common command finalization. It does not authorize arbitrary device-memory access outside the isolated emulator."
    }
    (out/"memaddr-unicorn-differential.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(acceptance,indent=2,sort_keys=True))
    return 0 if report["all_acceptance_pass"] else 3

if __name__=="__main__":
    raise SystemExit(main())
