#!/usr/bin/env python3
"""Instruction-level validation of 88W8964 UPDATE_ENCRYPTION action marshalling.

Executes the real action handler at 0x34d2c and stops exactly at the recovered
downstream helper boundary. No crypto/RF helper is stubbed or executed.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR,
)

START=0x34D2C
ENABLE_HELPER=0x28F54
REMOVE_HELPER=0x29070
SET_KEY_HELPER=0x29114
HELPERS={ENABLE_HELPER:"enable",REMOVE_HELPER:"remove",SET_KEY_HELPER:"set-key"}
PAGE=0x1000
CMD_ADDR=0x10000000
STACK_ADDR=0x10010000
RETURN_ADDR=0x10020000
COMMAND_ID=0x1122

ENABLE_MAP={0:1,1:0,2:0,3:0,4:3,5:0,6:4,7:4,8:6,9:5,10:7,11:8,12:0}

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

def base_cmd(size:int,action:int,macid:int)->bytearray:
    b=bytearray(size)
    struct.pack_into("<HH",b,0,COMMAND_ID,size)
    b[5]=macid&0xff
    struct.pack_into("<I",b,8,action&0xffffffff)
    return b

def make_enable(encr_type:int,macid:int=7,mac:bytes=b"\x02\x11\x22\x33\x44\x55")->bytes:
    b=base_cmd(80,0,macid)
    b[16:22]=mac
    b[22]=encr_type&0xff
    return bytes(b)

def make_key(action:int,key_type:int,key_index:int,key_len:int,macid:int=9,
             mac:bytes=b"\x02\xaa\xbb\xcc\xdd\xee")->bytes:
    b=base_cmd(80,action,macid)
    struct.pack_into("<H",b,16,64)
    struct.pack_into("<H",b,18,key_type&0xffff)
    struct.pack_into("<I",b,20,0x00000008)
    struct.pack_into("<I",b,24,key_index&0xffffffff)
    struct.pack_into("<H",b,28,key_len&0xffff)
    b[30:74]=bytes((i*13+5)&0xff for i in range(44))
    b[74:80]=mac
    return bytes(b)

def execute_to_helper(elf:Path,request:bytes)->dict[str,Any]:
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM|UC_MODE_LITTLE_ENDIAN)
    for va,blob in elf_load_segments(elf):
        map_blob(uc,va,blob)
    uc.mem_map(CMD_ADDR,PAGE)
    uc.mem_map(STACK_ADDR,PAGE)
    uc.mem_map(RETURN_ADDR,PAGE)
    uc.mem_write(CMD_ADDR,request)
    initial_sp=STACK_ADDR+PAGE-0x100
    uc.reg_write(UC_ARM_REG_R0,CMD_ADDR)
    uc.reg_write(UC_ARM_REG_SP,initial_sp)
    uc.reg_write(UC_ARM_REG_LR,RETURN_ADDR)
    stopped={"target":None}
    executed=[]
    def on_code(uc:Uc,address:int,size:int,user):
        if len(executed)<160:
            executed.append(address)
        if address in HELPERS:
            stopped["target"]=address
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.emu_start(START,0xffffffff,count=1000)
    if stopped["target"] is None:
        raise RuntimeError("action handler did not reach a recognized helper")
    sp=uc.reg_read(UC_ARM_REG_SP)
    regs={
        "r0":uc.reg_read(UC_ARM_REG_R0),
        "r1":uc.reg_read(UC_ARM_REG_R1),
        "r2":uc.reg_read(UC_ARM_REG_R2),
        "r3":uc.reg_read(UC_ARM_REG_R3),
        "sp":sp,
        "lr":uc.reg_read(UC_ARM_REG_LR),
    }
    stack_words=list(struct.unpack("<III",bytes(uc.mem_read(sp,12)))) if stopped["target"]==SET_KEY_HELPER else []
    return {
        "helper":stopped["target"],
        "helper_name":HELPERS[stopped["target"]],
        "regs":regs,
        "stack_words":stack_words,
        "executed_addresses":[f"0x{x:08x}" for x in executed],
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)

    enable_cases=[]
    enable_ok=True
    mac=b"\x02\x11\x22\x33\x44\x55"
    for encr_type,expected_mode in ENABLE_MAP.items():
        r=execute_to_helper(elf,make_enable(encr_type,macid=7,mac=mac))
        observed_mac=bytes(Uc(UC_ARCH_ARM,UC_MODE_ARM).mem_read(0,0)) if False else mac
        ok=(r["helper"]==ENABLE_HELPER and r["regs"]["r0"]==CMD_ADDR+16 and
            r["regs"]["r1"]==expected_mode and r["regs"]["r2"]==7)
        enable_ok &= ok
        enable_cases.append({
            "input_encr_type":encr_type,
            "expected_internal_mode":expected_mode,
            "actual_internal_mode":r["regs"]["r1"],
            "mac_pointer":f"0x{r['regs']['r0']:08x}",
            "macid":r["regs"]["r2"],
            "helper":f"0x{r['helper']:08x}",
            "match":ok,
        })

    remove_req=make_key(2,0x0102,0x12345678,0x0110,macid=9)
    remove=execute_to_helper(elf,remove_req)
    remove_ok=(remove["helper"]==REMOVE_HELPER and remove["regs"]["r0"]==CMD_ADDR+74 and remove["regs"]["r1"]==9)

    key_cases=[]
    key_ok=True
    for action,group_flag in ((1,0),(3,1)):
        req=make_key(action,0x0102,0x12345678,0x0110,macid=9)
        r=execute_to_helper(elf,req)
        expected=[0x10,9,group_flag]
        ok=(
            r["helper"]==SET_KEY_HELPER and
            r["regs"]["r0"]==CMD_ADDR+74 and
            r["regs"]["r1"]==CMD_ADDR+30 and
            r["regs"]["r2"]==0x02 and
            r["regs"]["r3"]==0x78 and
            r["stack_words"]==expected
        )
        key_ok &= ok
        key_cases.append({
            "action_type":action,
            "group_flag":group_flag,
            "helper":f"0x{r['helper']:08x}",
            "mac_pointer":f"0x{r['regs']['r0']:08x}",
            "key_pointer":f"0x{r['regs']['r1']:08x}",
            "key_type_low8":r["regs"]["r2"],
            "key_index_low8":r["regs"]["r3"],
            "stack_words":r["stack_words"],
            "expected_stack_words":expected,
            "match":ok,
        })

    acceptance={
        "all_enable_type_mappings_match":enable_ok,
        "remove_key_marshalling_matches":remove_ok,
        "set_and_group_key_marshalling_match":key_ok,
        "key_fields_are_truncated_to_low8_as_observed":all(
            c["key_type_low8"]==2 and c["key_index_low8"]==0x78 and c["stack_words"][0]==0x10
            for c in key_cases
        ),
    }
    report={
        "schema":"wrt8964-update-encryption-unicorn-boundary/v1",
        "engine":"Unicorn 2.1.4 ARM",
        "start":"0x00034d2c",
        "scope":"Actual UPDATE_ENCRYPTION action handler execution through action-specific argument marshalling, stopping before downstream helpers.",
        "enable_cases":enable_cases,
        "remove_case":{
            "helper":f"0x{remove['helper']:08x}",
            "mac_pointer":f"0x{remove['regs']['r0']:08x}",
            "macid":remove["regs"]["r1"],
            "match":remove_ok,
        },
        "key_cases":key_cases,
        "acceptance":acceptance,
        "all_acceptance_pass":all(acceptance.values()),
        "guardrail":"No encryption/key-management helper is stubbed or executed. This validates only real machine-code action selection and helper argument marshalling."
    }
    (out/"update-encryption-unicorn-boundary.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(acceptance,indent=2,sort_keys=True))
    return 0 if report["all_acceptance_pass"] else 3

if __name__=="__main__":
    raise SystemExit(main())
