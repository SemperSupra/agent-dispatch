#!/usr/bin/env python3
"""Instruction-level differential validation of recovered GET_HW_SPEC response fields."""
from __future__ import annotations

import argparse
import importlib.util
import json
import struct
from pathlib import Path
from typing import Any

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R10, UC_ARM_REG_SP

SEM_PATH=Path(__file__).with_name("wrt3200acm_gethwspec_semantics.py")
SPEC=importlib.util.spec_from_file_location("gethw_sem",SEM_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load GET_HW_SPEC semantic model")
sem=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(sem)

START=0x38148
STOP_BEFORE_POST_FILL=0x381D0
PAGE=0x1000
CMD_ADDR=0x10000000
STATE_ADDR=0x10010000
STACK_ADDR=0x10020000

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

def fields(buf:bytes)->dict[str,Any]:
    return {
        "version":buf[8],
        "host_if":buf[9],
        "num_mcast_addr":struct.unpack_from("<H",buf,12)[0],
        "region_code":struct.unpack_from("<H",buf,20)[0],
        "num_antenna":struct.unpack_from("<H",buf,22)[0],
        "fw_release_num":struct.unpack_from("<I",buf,24)[0],
        "wcb_base0":struct.unpack_from("<I",buf,28)[0],
        "fw_awake_cookie_low_byte":buf[40],
    }

def run_case(elf:Path,region_code:int,num_mcast:int,cookie:int)->dict[str,Any]:
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN)
    for va,blob in elf_load_segments(elf):
        map_blob(uc,va,blob)
    uc.mem_map(CMD_ADDR,PAGE)
    uc.mem_map(STATE_ADDR,PAGE)
    uc.mem_map(STACK_ADDR,PAGE)
    req=bytearray(sem.make_request(fw_awake_cookie=cookie))
    uc.mem_write(CMD_ADDR,bytes(req))
    state=bytearray(PAGE)
    struct.pack_into("<H",state,0xf8,region_code&0xffff)
    uc.mem_write(STATE_ADDR,bytes(state))
    uc.reg_write(UC_ARM_REG_R4,CMD_ADDR)
    uc.reg_write(UC_ARM_REG_R5,STATE_ADDR)
    uc.reg_write(UC_ARM_REG_R10,num_mcast&0xffffffff)
    uc.reg_write(UC_ARM_REG_SP,STACK_ADDR+PAGE-0x100)

    stopped={"ok":False}
    executed=[]
    def on_code(uc,address,size,user):
        if len(executed)<128:
            executed.append(address)
        if address==STOP_BEFORE_POST_FILL:
            stopped["ok"]=True
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.emu_start(START,STOP_BEFORE_POST_FILL+4,count=1000)
    out=bytes(uc.mem_read(CMD_ADDR,len(req)))
    actual=fields(out)

    expected_buf,_=sem.partial_rehost(
        bytes(req),
        internal_mac=b"\x00\x11\x22\x33\x44\x55",
        region_code=region_code,
        num_mcast_addr=num_mcast,
        host_if=2,
    )
    expected=fields(expected_buf)
    return {
        "inputs":{"region_code":region_code,"num_mcast_addr":num_mcast,"fw_awake_cookie":cookie},
        "actual":actual,
        "expected":expected,
        "field_match":actual==expected,
        "reached_post_fill_boundary":stopped["ok"],
        "executed_addresses":[f"0x{x:08x}" for x in executed],
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf)
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    cases=[
        run_case(elf,0x0010,32,0x00000000),
        run_case(elf,0x1234,0x55aa,0x000000a0),
    ]
    acceptance={
        "all_field_sets_match_semantic_model":all(c["field_match"] for c in cases),
        "all_runs_reach_post_fill_boundary":all(c["reached_post_fill_boundary"] for c in cases),
        "host_if_is_constant_2":all(c["actual"]["host_if"]==2 for c in cases),
        "fw_release_is_9_3_2_12":all(c["actual"]["fw_release_num"]==0x0903020c for c in cases),
        "num_antenna_is_3":all(c["actual"]["num_antenna"]==3 for c in cases),
    }
    report={
        "schema":"wrt8964-gethwspec-unicorn-differential/v1",
        "engine":"Unicorn 2.1.4 ARM",
        "start":"0x00038148",
        "stop_before_post_fill":"0x000381d0",
        "scope":"Directly recovered fixed response-field block plus host_if helper 0x0000e350; excludes permanent-address branch and post-fill global allocator 0x0003b038.",
        "cases":cases,
        "acceptance":acceptance,
        "all_acceptance_pass":all(acceptance.values()),
        "guardrail":"This validates only the response fields executed in 0x38148..0x381cc. Unknown fields and global-allocation side effects remain outside this rehost."
    }
    (out/"gethwspec-unicorn-differential.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(acceptance,indent=2,sort_keys=True))
    return 0 if report["all_acceptance_pass"] else 3

if __name__=="__main__":
    raise SystemExit(main())
