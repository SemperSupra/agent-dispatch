#!/usr/bin/env python3
"""Evidence-backed partial semantics and rehost for 88W8964 GET_HW_SPEC (0x0003)."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import struct
from pathlib import Path
from typing import Any

_HELPER_PATH=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
_SPEC=importlib.util.spec_from_file_location("dispatch_probe_local",_HELPER_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot load wrt3200acm_dispatch_probe.py")
dispatch=importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(dispatch)

HANDLER_START=0x38064
HANDLER_END=0x381E8
COMMAND_ID=0x0003

# struct hostcmd_header is 8 bytes.
VERSION_OFF=8
HOST_IF_OFF=9
NUM_WCB_OFF=10
NUM_MCAST_OFF=12
PERMANENT_ADDR_OFF=14
REGION_CODE_OFF=20
NUM_ANTENNA_OFF=22
FW_RELEASE_OFF=24
WCB_BASE0_OFF=28
RXPD_WR_PTR_OFF=32
RXPD_RD_PTR_OFF=36
FW_AWAKE_COOKIE_OFF=40

def read_elf_load_u32(elf:Path,address:int)->int:
    data=elf.read_bytes()
    if data[:4]!=b"\x7fELF" or data[4]!=1 or data[5]!=1:
        raise ValueError("expected ELF32 little-endian")
    phoff=struct.unpack_from("<I",data,28)[0]
    phentsize=struct.unpack_from("<H",data,42)[0]
    phnum=struct.unpack_from("<H",data,44)[0]
    for i in range(phnum):
        off=phoff+i*phentsize
        p_type,p_offset,p_vaddr,_paddr,p_filesz,_memsz,_flags,_align=struct.unpack_from("<IIIIIIII",data,off)
        if p_type==1 and p_vaddr<=address and address+4<=p_vaddr+p_filesz:
            return struct.unpack_from("<I",data,p_offset+(address-p_vaddr))[0]
    raise ValueError(f"address 0x{address:x} not in PT_LOAD")

def verify_disassembly(text:str,elf:Path)->dict[str,Any]:
    anchors={
        "request_mac_first_byte_at_14":r"380bc:.*ldrb\s+r0, \[r4, #14\]",
        "broadcast_mac_sentinel_ff":r"380c0:.*cmp\s+r0, #255",
        "copy_request_mac_to_internal":r"380c8:.*add\s+r1, r4, #14[\s\S]*380cc:.*add\s+r0, r5, #34[\s\S]*380d0:.*bl\s+0x25f0",
        "copy_internal_mac_to_response":r"381d8:.*add\s+r1, r5, #34[\s\S]*381dc:.*add\s+r0, r4, #14[\s\S]*381e0:.*bl\s+0x25f0",
        "num_antenna_3_low":r"38148:.*mov\s+r0, #3[\s\S]*3814c:.*strb\s+r0, \[r4, #22\]",
        "num_antenna_high_zero":r"38150:.*mov\s+r3, #0[\s\S]*38154:.*strb\s+r3, \[r4, #23\]",
        "num_mcast_from_r10":r"38158:.*lsr\s+r12, r10, #8[\s\S]*3815c:.*strb\s+r10, \[r4, #12\][\s\S]*38164:.*strb\s+r12, \[r4, #13\]",
        "version_7":r"38160:.*mov\s+r2, #7[\s\S]*38168:.*strb\s+r2, \[r4, #8\]",
        "host_if_helper":r"3816c:.*bl\s+0xe350[\s\S]*38170:.*strb\s+r0, \[r4, #9\]",
        "region_code_internal":r"38174:.*ldrh\s+r1, \[r5, #248\][\s\S]*3817c:.*strb\s+r1, \[r4, #20\][\s\S]*38184:.*strb\s+r6, \[r4, #21\]",
        "fw_release_literal_load":r"38178:.*ldr\s+r2, \[pc, #556\].*@ 0x383ac",
        "fw_release_store":r"3818c:.*strb\s+r2, \[r4, #24\][\s\S]*38194:.*strb\s+r12, \[r4, #25\][\s\S]*3819c:.*strb\s+r3, \[r4, #26\][\s\S]*381a4:.*strb\s+r5, \[r4, #27\]",
        "wcb_base0_0x2000":r"381a0:.*mov\s+r1, #8192[\s\S]*381c0:.*strb\s+r1, \[r4, #28\][\s\S]*381c4:.*strb\s+r2, \[r4, #29\][\s\S]*381c8:.*strb\s+r3, \[r4, #30\][\s\S]*381cc:.*strb\s+r12, \[r4, #31\]",
        "awake_cookie_low_bit_set":r"381ac:.*ldrb\s+r0, \[r4, #40\][\s\S]*381b8:.*orr\s+r5, r0, #1[\s\S]*381bc:.*strb\s+r5, \[r4, #40\]",
        "post_fill_helper":r"381d0:.*bl\s+0x3b038",
    }
    observed={k:bool(re.search(v,text,re.M)) for k,v in anchors.items()}
    literal=read_elf_load_u32(elf,0x383AC)
    return {
        "anchors":observed,
        "missing":[k for k,v in observed.items() if not v],
        "fw_release_literal_address":"0x000383ac",
        "fw_release_literal":f"0x{literal:08x}",
        "fw_release_literal_matches_9_3_2_12":literal==0x0903020c,
        "all_required_present":all(observed.values()) and literal==0x0903020c,
    }

def partial_rehost(request:bytes|bytearray,*,internal_mac:bytes,region_code:int,num_mcast_addr:int,host_if:int)->tuple[bytes,dict[str,Any]]:
    if len(internal_mac)!=6:
        raise ValueError("internal_mac must be 6 bytes")
    out=bytearray(request)
    if len(out)<44:
        out.extend(b"\x00"*(44-len(out)))
    request_mac=bytes(out[PERMANENT_ADDR_OFF:PERMANENT_ADDR_OFF+6])
    state_change={}
    if request_mac and request_mac[0]==0xff:
        out[PERMANENT_ADDR_OFF:PERMANENT_ADDR_OFF+6]=internal_mac
    else:
        state_change["internal_mac"]=request_mac.hex(":")
    out[VERSION_OFF]=7
    out[HOST_IF_OFF]=host_if&0xff
    struct.pack_into("<H",out,NUM_MCAST_OFF,num_mcast_addr&0xffff)
    struct.pack_into("<H",out,REGION_CODE_OFF,region_code&0xffff)
    struct.pack_into("<H",out,NUM_ANTENNA_OFF,3)
    struct.pack_into("<I",out,FW_RELEASE_OFF,0x0903020c)
    struct.pack_into("<I",out,WCB_BASE0_OFF,0x2000)
    out[FW_AWAKE_COOKIE_OFF] |= 1
    unknown={
        "num_wcb":True,
        "rxpd_wr_ptr":True,
        "rxpd_rd_ptr":True,
        "post_fill_helper_0x3b038_effects":True,
        "wcb_base_array":True,
    }
    return bytes(out),{"state_change":state_change,"unknown_fields":unknown}

def make_request(permanent_addr:bytes=b"\xff"*6,fw_awake_cookie:int=0)->bytes:
    if len(permanent_addr)!=6:
        raise ValueError("permanent_addr must be 6 bytes")
    b=bytearray(128)
    struct.pack_into("<HH",b,0,COMMAND_ID,128)
    b[PERMANENT_ADDR_OFF:PERMANENT_ADDR_OFF+6]=permanent_addr
    struct.pack_into("<I",b,FW_AWAKE_COOKIE_OFF,fw_awake_cookie)
    return bytes(b)

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    disasm=dispatch.run_objdump(elf,HANDLER_START,HANDLER_END)
    v=verify_disassembly(disasm,elf)
    report={
        "schema":"wrt8964-get-hw-spec-semantics/v1",
        "command":{"id":"0x0003","handler_start":"0x00038064","handler_end":"0x000381e8"},
        "host_layout":{
            "version":VERSION_OFF,"host_if":HOST_IF_OFF,"num_wcb":NUM_WCB_OFF,
            "num_mcast_addr":NUM_MCAST_OFF,"permanent_addr":PERMANENT_ADDR_OFF,
            "region_code":REGION_CODE_OFF,"num_antenna":NUM_ANTENNA_OFF,
            "fw_release_num":FW_RELEASE_OFF,"wcb_base0":WCB_BASE0_OFF,
            "rxpd_wr_ptr":RXPD_WR_PTR_OFF,"rxpd_rd_ptr":RXPD_RD_PTR_OFF,
            "fw_awake_cookie":FW_AWAKE_COOKIE_OFF
        },
        "observed_semantics":{
            "permanent_addr":"If request byte +14 is 0xff, copies 6-byte internal address from state +0x22 into response +14; otherwise copies request +14..+19 into internal state +0x22.",
            "version":7,
            "host_if":"result byte of helper 0x0000e350",
            "num_mcast_addr":"16-bit value carried in r10",
            "region_code":"16-bit value from internal state +0xf8",
            "num_antenna":3,
            "fw_release_num":"0x0903020c (bytes 0c 02 03 09 => 9.3.2.12)",
            "wcb_base0":"0x00002000",
            "fw_awake_cookie":"sets bit 0 of response byte +40 before helper 0x0003b038"
        },
        "unknowns":[
            "num_wcb output semantics",
            "exact semantics of helper 0x0000e350 producing host_if",
            "rxpd_wr_ptr/rxpd_rd_ptr population",
            "effects of post-fill helper 0x0003b038",
            "wcb_base[] population beyond wcb_base0"
        ],
        "verification":v,
        "guardrail":"partial_rehost writes only fields with directly recovered semantics and reports the rest UNKNOWN."
    }
    (out/"get-hw-spec-semantics.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    (out/"get-hw-spec-disassembly.txt").write_text(disasm)
    print(json.dumps(v,indent=2,sort_keys=True))
    return 0 if v["all_required_present"] else 3

if __name__=="__main__":
    raise SystemExit(main())
