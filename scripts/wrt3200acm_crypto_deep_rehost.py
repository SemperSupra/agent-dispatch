#!/usr/bin/env python3
"""Execute real UPDATE_ENCRYPTION firmware through helpers until the first unsupported dependency."""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path
from typing import Any
from unicorn import (
    Uc,UcError,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_LITTLE_ENDIAN,
    UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED,UC_HOOK_MEM_WRITE_UNMAPPED,UC_HOOK_MEM_FETCH_UNMAPPED
)
from unicorn.arm_const import (
    UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
    UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
)

PAGE=0x1000; START=0x34D2C
CMD=0x10000000; STACK=0x10010000; RET=0x10020000
COMMAND_ID=0x1122

def align_up(x,a=PAGE):return (x+a-1)&~(a-1)

def segments(path:Path):
    d=path.read_bytes()
    if d[:4]!=b"\x7fELF" or d[4]!=1 or d[5]!=1:raise ValueError("expected ELF32 LE")
    phoff=struct.unpack_from("<I",d,28)[0]; ents=struct.unpack_from("<H",d,42)[0]; n=struct.unpack_from("<H",d,44)[0]
    out=[]
    for i in range(n):
        off=phoff+i*ents
        typ,fo,va,_pa,fs,ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,off)
        if typ==1 and fs:out.append((va,d[fo:fo+fs],ms))
    return out

def map_region(uc,address,size,mapped:set[int]):
    b=address&~(PAGE-1); e=align_up(address+size)
    for p in range(b,e,PAGE):
        if p not in mapped:uc.mem_map(p,PAGE);mapped.add(p)

def request(action:int,key_type:int=2,key_index:int=1,key_len:int=16,key_info:int=8,macid:int=9,encr_type:int=6):
    b=bytearray(80)
    struct.pack_into("<HH",b,0,COMMAND_ID,80);b[5]=macid
    struct.pack_into("<I",b,8,action)
    if action==0:
        b[16:22]=b"\x02\x11\x22\x33\x44\x55";b[22]=encr_type
    else:
        struct.pack_into("<H",b,16,64);struct.pack_into("<H",b,18,key_type)
        struct.pack_into("<I",b,20,key_info);struct.pack_into("<I",b,24,key_index)
        struct.pack_into("<H",b,28,key_len)
        b[30:74]=bytes((i*13+5)&255 for i in range(44))
        b[74:80]=b"\x02\xaa\xbb\xcc\xdd\xee"
    return bytes(b)

def execute(elf:Path,req:bytes,count=6000):
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN);mapped=set()
    load_ranges=[]
    for va,blob,ms in segments(elf):
        map_region(uc,va,max(ms,len(blob)),mapped);uc.mem_write(va,blob);load_ranges.append((va,va+max(ms,len(blob))))
    for a in (CMD,STACK,RET):map_region(uc,a,PAGE,mapped)
    uc.mem_write(CMD,req);uc.reg_write(UC_ARM_REG_R0,CMD);uc.reg_write(UC_ARM_REG_SP,STACK+0xf00);uc.reg_write(UC_ARM_REG_LR,RET)
    trace=[];mem=[];last_pc=None;stop={"kind":None};helper_hits=[]
    interesting={0x28f54:"enable",0x29070:"remove",0x29114:"set-key",0x3fb34:"shared",0x44148:"set-key-leaf",0x44230:"remove-key-leaf"}
    def on_code(uc,a,size,user):
        nonlocal last_pc
        last_pc=a
        if len(trace)<2500:trace.append(a)
        if a in interesting:helper_hits.append({"address":a,"name":interesting[a]})
        if a==RET:
            stop.update(kind="returned-to-sentinel",pc=a);uc.emu_stop()
    def on_mem(uc,access,a,size,value,user):
        if len(mem)<2500:mem.append({"access":access,"address":a,"size":size,"value":value,"pc":uc.reg_read(UC_ARM_REG_PC)})
    def on_unmapped(uc,access,a,size,value,user):
        stop.update(kind="unmapped-memory",access=access,address=a,size=size,value=value,pc=last_pc)
        return False
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,on_mem)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED,on_unmapped)
    try:
        uc.emu_start(START,0xffffffff,count=count)
        if stop["kind"] is None:stop.update(kind="instruction-cap-or-natural-stop",pc=last_pc)
    except UcError as e:
        if stop["kind"] is None:stop.update(kind="unicorn-error",error=str(e),pc=last_pc)
    regs={f"r{i}":uc.reg_read(r) for i,r in enumerate([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3])}
    regs.update(sp=uc.reg_read(UC_ARM_REG_SP),lr=uc.reg_read(UC_ARM_REG_LR),pc=uc.reg_read(UC_ARM_REG_PC))
    return {
      "stop":stop,"helper_hits":helper_hits,"registers":regs,
      "instruction_count_recorded":len(trace),"memory_access_count_recorded":len(mem),
      "trace":[f"0x{x:08x}" for x in trace],
      "memory_accesses":mem,
      "load_ranges":[[a,b] for a,b in load_ranges]
    }

def sig(r):
    return {
      "stop":r["stop"],
      "helper_hits":r["helper_hits"],
      "trace":r["trace"],
      "memory_accesses":r["memory_accesses"],
    }

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--elf",required=True);ap.add_argument("--out",required=True);ns=ap.parse_args()
    elf=Path(ns.elf);out=Path(ns.out);out.mkdir(parents=True,exist_ok=True)
    cases={
      "enable_tkip":request(0,encr_type=4),
      "enable_aes":request(0,encr_type=6),
      "set_wep":request(1,key_type=0,key_index=1,key_len=5,key_info=0x01000000),
      "set_tkip":request(1,key_type=1,key_index=0,key_len=32,key_info=0x02000048),
      "set_aes_pairwise":request(1,key_type=2,key_index=0,key_len=16,key_info=0x8),
      "set_aes_pairwise_keyinfo_zero":request(1,key_type=2,key_index=0,key_len=16,key_info=0),
      "set_aes_group":request(3,key_type=2,key_index=1,key_len=16,key_info=0x4),
      "remove_group":request(2,key_type=0,key_index=0,key_len=0,key_info=0x6),
    }
    results={k:execute(elf,v) for k,v in cases.items()}
    # Up to the first unsupported dependency, test whether key_info changes control/memory behavior.
    a=sig(results["set_aes_pairwise"]);b=sig(results["set_aes_pairwise_keyinfo_zero"])
    key_info_invariant=(a==b)
    summary={k:{
      "stop":v["stop"],"helper_hits":v["helper_hits"],
      "instruction_count_recorded":v["instruction_count_recorded"],
      "memory_access_count_recorded":v["memory_access_count_recorded"]
    } for k,v in results.items()}
    report={
      "schema":"wrt8964-update-encryption-deep-rehost/v1",
      "engine":"Unicorn 2.1.4 ARM",
      "scope":"Real firmware execution from UPDATE_ENCRYPTION action handler through recovered helpers until return, instruction cap, or first unmapped dependency. No unsupported memory is mapped on demand.",
      "cases":results,
      "summary":summary,
      "key_info_invariant_to_first_dependency":key_info_invariant,
      "guardrail":"Zero-initialized scratch contains only the command/stack; firmware load segments retain real bytes. Any unmapped dependency terminates the case rather than being guessed."
    }
    (out/"update-encryption-deep-rehost.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"summary":summary,"key_info_invariant_to_first_dependency":key_info_invariant},indent=2,sort_keys=True))
    return 0
if __name__=="__main__":raise SystemExit(main())
