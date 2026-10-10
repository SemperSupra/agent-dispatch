#!/usr/bin/env python3
"""Evidence-backed semantics and bounded rehost for 88W8964 MEM_ADDR_ACCESS."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import struct
from pathlib import Path
from typing import Callable, Any

_HELPER_PATH=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
_SPEC=importlib.util.spec_from_file_location("dispatch_probe_local",_HELPER_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot load wrt3200acm_dispatch_probe.py")
dispatch=importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(dispatch)

HANDLER_START=0x37DE8
HANDLER_END=0x37F58
COMMAND_ID=0x001D
HEADER_SIZE=8
ADDRESS_OFF=8
LENGTH_OFF=12
SELECTOR_OFF=14
VALUES_OFF=16
MAX_WORDS=64
SELECTOR2_BYTES=256

def read_elf_load_u32(elf:Path,address:int)->int:
    d=elf.read_bytes()
    if d[:4]!=b"\x7fELF" or d[4]!=1 or d[5]!=1:
        raise ValueError("expected ELF32 little-endian")
    phoff=struct.unpack_from("<I",d,28)[0]
    phentsize=struct.unpack_from("<H",d,42)[0]
    phnum=struct.unpack_from("<H",d,44)[0]
    for i in range(phnum):
        off=phoff+i*phentsize
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,off)
        if typ==1 and va<=address and address+4<=va+fs:
            return struct.unpack_from("<I",d,fo+(address-va))[0]
    raise ValueError(f"address 0x{address:x} not in PT_LOAD")

def parse_command(buf:bytes|bytearray)->dict[str,int]:
    if len(buf)<VALUES_OFF:
        raise ValueError("command buffer shorter than MEM_ADDR_ACCESS prefix")
    cmd,header_len=struct.unpack_from("<HH",buf,0)
    return {
        "cmd":cmd,
        "header_len":header_len,
        "address":struct.unpack_from("<I",buf,ADDRESS_OFF)[0],
        "count":struct.unpack_from("<H",buf,LENGTH_OFF)[0],
        "selector":struct.unpack_from("<H",buf,SELECTOR_OFF)[0],
    }

def make_request(address:int,count:int,selector:int=0,header_len:int=272,value0:int=0)->bytes:
    buf=bytearray(max(header_len,VALUES_OFF+4*max(count,1)))
    struct.pack_into("<HH",buf,0,COMMAND_ID,header_len)
    struct.pack_into("<I",buf,ADDRESS_OFF,address&0xffffffff)
    struct.pack_into("<H",buf,LENGTH_OFF,count&0xffff)
    struct.pack_into("<H",buf,SELECTOR_OFF,selector&0xffff)
    struct.pack_into("<I",buf,VALUES_OFF,value0&0xffffffff)
    return bytes(buf)

def execute(
    buf:bytes|bytearray,
    *,
    read32:Callable[[int],int]|None=None,
    write32:Callable[[int,int],None]|None=None,
    read_block:Callable[[int,int],bytes]|None=None,
    selector3_values:tuple[int,int]|None=None,
)->bytes:
    f=parse_command(buf)
    if f["cmd"]&0x7fff!=COMMAND_ID:
        raise ValueError(f"not MEM_ADDR_ACCESS: 0x{f['cmd']:04x}")
    out=bytearray(buf)
    if len(out)<VALUES_OFF+SELECTOR2_BYTES:
        out.extend(b"\x00"*(VALUES_OFF+SELECTOR2_BYTES-len(out)))

    if f["selector"]==0:
        if read32 is None:
            raise ValueError("selector 0 requires read32")
        if f["count"]>MAX_WORDS:
            raise ValueError("firmware rejects MEM_ADDR_ACCESS length > 64")
        for i in range(f["count"]):
            struct.pack_into("<I",out,VALUES_OFF+4*i,read32((f["address"]+4*i)&0xffffffff)&0xffffffff)
        return bytes(out)

    if f["selector"]==1:
        if write32 is None:
            raise ValueError("selector 1 requires write32")
        write32(f["address"],struct.unpack_from("<I",out,VALUES_OFF)[0])
        return bytes(out)

    if f["selector"]==2:
        if read_block is None:
            raise ValueError("selector 2 requires read_block")
        block=read_block(f["address"],SELECTOR2_BYTES)
        if len(block)!=SELECTOR2_BYTES:
            raise ValueError("selector 2 requires exactly 256 bytes")
        out[VALUES_OFF:VALUES_OFF+SELECTOR2_BYTES]=block
        return bytes(out)

    if f["selector"]==3:
        if selector3_values is None:
            raise ValueError("selector 3 requires recovered literal values")
        struct.pack_into("<I",out,VALUES_OFF,selector3_values[0]&0xffffffff)
        struct.pack_into("<I",out,VALUES_OFF+8,selector3_values[1]&0xffffffff)
        return bytes(out)

    raise ValueError(f"unsupported selector {f['selector']}")

def verify_disassembly(handler:str,dispatcher_tail:str)->dict[str,Any]:
    joined=handler+"\n"+dispatcher_tail
    anchors={
        "selector_decode":r"37e00:.*\[r4, #15\][\s\S]*37e04:.*\[r4, #14\]",
        "selector0_length_cap":r"37e38:.*cmp\s+r2, #64",
        "selector0_read32":r"37e68:.*ldr\s+r3, \[r1\], #4",
        "selector1_address_value":all(
            re.search(p, joined, re.M) for p in (
                r"37eac:.*ldrb\s+r1, \[r4, #8\]",
                r"37eb0:.*ldrb\s+r8, \[r4, #9\]",
                r"37ebc:.*ldrb\s+r2, \[r4, #10\]",
                r"37ecc:.*ldrb\s+r3, \[r4, #11\]",
                r"37ec0:.*ldrb\s+r6, \[r4, #16\]",
                r"37eb4:.*ldrb\s+r12, \[r4, #17\]",
                r"37ec8:.*ldrb\s+r5, \[r4, #18\]",
                r"37ed4:.*ldrb\s+r7, \[r4, #19\]",
                r"37ec4:.*orr\s+r0, r0, r8, lsl #8",
                r"37ed8:.*orr\s+r0, r0, r2, lsl #16",
                r"37ee0:.*orr\s+r0, r0, r3, lsl #24",
                r"37ed0:.*orr\s+r1, r6, r12, lsl #8",
                r"37edc:.*orr\s+r1, r1, r5, lsl #16",
                r"37ee4:.*orr\s+r1, r1, r7, lsl #24",
                r"37ee8:.*b\s+0x3872c",
            )
        ),
        "selector1_store32":r"3872c:.*str\s+r1, \[r0\]",
        "selector2_dest_value_array":r"37f00:.*add\s+r0, r4, #16",
        "selector2_size_256":r"37f08:.*mov\s+r2, #256",
        "selector2_branch_copy":r"37f10:.*b\s+0x38a6c",
        "selector2_copy_call":r"38a6c:.*bl\s+0x25f0",
        "selector3_literal_a":r"37f14:.*@ 0x383a8",
        "selector3_literal_b":r"37f18:.*@ 0x38384",
        "selector3_store_value0":r"37f1c:.*\[r4, #16\]",
        "selector3_store_value2":r"37f24:.*\[r4, #24\]",
    }
    observed={k:(v if isinstance(v,bool) else bool(re.search(v,joined,re.M))) for k,v in anchors.items()}
    return {"anchors":observed,"missing":[k for k,v in observed.items() if not v],"all_required_present":all(observed.values())}

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    handler=dispatch.run_objdump(elf,HANDLER_START,HANDLER_END)
    tail=dispatch.run_objdump(elf,0x3871c,0x38a74)
    memcpy_disasm=dispatch.run_objdump(elf,0x25f0,0x2664)
    verification=verify_disassembly(handler,tail)
    selector3=(read_elf_load_u32(elf,0x383a8),read_elf_load_u32(elf,0x38384))
    report={
        "schema":"wrt8964-mem-addr-access-semantics/v2",
        "firmware_handler":{"command_id":"0x001d","start":"0x00037de8","end":"0x00037f58"},
        "host_layout":{
            "header_size":HEADER_SIZE,
            "address":{"offset":ADDRESS_OFF,"size":4,"encoding":"little-endian"},
            "length":{"offset":LENGTH_OFF,"size":2,"encoding":"little-endian","unit":"32-bit words","selector0_max":64},
            "selector":{"offset":SELECTOR_OFF,"size":2,"encoding":"little-endian"},
            "value":{"offset":VALUES_OFF,"element_size":4,"count":64,"encoding":"little-endian"},
            "source":"kaloz/mwlwifi@db97edf20fadea2617805006f5230665fadc6a8c hif/hostcmd.h"
        },
        "selector_semantics":{
            "0":{"status":"observed","behavior":"Read length sequential 32-bit words from address and return them in value[].","max_words":64},
            "1":{"status":"observed","behavior":"Write value[0] as a 32-bit word directly to address.","terminal_store":"0x0003872c: str r1,[r0]"},
            "2":{"status":"observed","behavior":"Copy exactly 256 bytes from address into response value[] at +16.","copy_path":"0x00038a6c -> 0x000025f0","bytes":256},
            "3":{"status":"observed","behavior":"Return two firmware literals in value[0] and value[2].","value0":f"0x{selector3[0]:08x}","value2":f"0x{selector3[1]:08x}","literal_addresses":["0x000383a8","0x00038384"]},
        },
        "disassembly_verification":verification,
        "memcpy_probe":{"instructions":dispatch.parse_instructions(memcpy_disasm)},
        "guardrail":"These semantics describe the directly recovered selector paths only. The optional pre-handler at 0x000363e4 remains outside the model unless its enabling state is present."
    }
    (out/"mem-addr-access-semantics.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    (out/"mem-addr-access-disassembly.txt").write_text(handler)
    (out/"mem-addr-access-selector-tail.txt").write_text(tail)
    (out/"memcpy-0x25f0.txt").write_text(memcpy_disasm)
    print(json.dumps({"verification":verification,"selector3":[f"0x{x:08x}" for x in selector3]},indent=2))
    return 0 if verification["all_required_present"] else 3

if __name__=="__main__":
    raise SystemExit(main())
