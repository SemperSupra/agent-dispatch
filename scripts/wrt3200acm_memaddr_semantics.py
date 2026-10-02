#!/usr/bin/env python3
"""Evidence-backed semantic probe and minimal rehost for 88W8964 MEM_ADDR_ACCESS.

Only selector 0 is modeled because its handler behavior is directly recoverable
from the pinned firmware and open host structure. Other selectors stay UNKNOWN.
"""
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

class UnknownSelector(NotImplementedError):
    pass

def parse_command(buf: bytes|bytearray) -> dict[str,int]:
    if len(buf)<VALUES_OFF:
        raise ValueError("command buffer shorter than 16-byte MEM_ADDR_ACCESS prefix")
    cmd,length_header=struct.unpack_from("<HH",buf,0)
    address=struct.unpack_from("<I",buf,ADDRESS_OFF)[0]
    count=struct.unpack_from("<H",buf,LENGTH_OFF)[0]
    selector=struct.unpack_from("<H",buf,SELECTOR_OFF)[0]
    return {"cmd":cmd,"header_len":length_header,"address":address,"count":count,"selector":selector}

def execute_selector0(buf: bytes|bytearray, read32: Callable[[int],int]) -> bytes:
    """Semantic rehost of the proven selector-0 path.

    The firmware caps length at 64 dwords, reads sequential 32-bit words from
    address + 4*i, and writes each result little-endian at response +16+4*i.
    """
    fields=parse_command(buf)
    if fields["cmd"] & 0x7fff != COMMAND_ID:
        raise ValueError(f"not MEM_ADDR_ACCESS: 0x{fields['cmd']:04x}")
    if fields["selector"] != 0:
        raise UnknownSelector(f"selector {fields['selector']} is intentionally not modeled")
    if fields["count"]>MAX_WORDS:
        raise ValueError("firmware rejects MEM_ADDR_ACCESS length > 64")
    out=bytearray(buf)
    need=VALUES_OFF+4*fields["count"]
    if len(out)<need:
        out.extend(b"\x00"*(need-len(out)))
    for i in range(fields["count"]):
        value=read32((fields["address"]+4*i)&0xffffffff)&0xffffffff
        struct.pack_into("<I",out,VALUES_OFF+4*i,value)
    return bytes(out)

def make_request(address:int,count:int,selector:int=0,header_len:int=272)->bytes:
    buf=bytearray(max(header_len,VALUES_OFF+4*count))
    struct.pack_into("<HH",buf,0,COMMAND_ID,header_len)
    struct.pack_into("<I",buf,ADDRESS_OFF,address&0xffffffff)
    struct.pack_into("<H",buf,LENGTH_OFF,count)
    struct.pack_into("<H",buf,SELECTOR_OFF,selector)
    return bytes(buf)

def verify_disassembly(text:str)->dict[str,Any]:
    anchors={
        "selector_high_byte_at_15":r"37e00:.*ldrb\s+r0, \[r4, #15\]",
        "selector_low_byte_at_14":r"37e04:.*ldrb\s+r1, \[r4, #14\]",
        "selector0_branch":r"37e0c:.*beq\s+0x37e2c",
        "selector1_compare":r"37e10:.*cmp\s+r0, #1",
        "selector2_compare":r"37e18:.*cmp\s+r0, #2",
        "selector3_compare":r"37e20:.*cmp\s+r0, #3",
        "length_high_at_13":r"37e2c:.*ldrb\s+r1, \[r4, #13\]",
        "length_low_at_12":r"37e30:.*ldrb\s+r0, \[r4, #12\]",
        "length_cap_64":r"37e38:.*cmp\s+r2, #64",
        "address_bytes_8_11":r"37e44:.*\[r4, #9\][\s\S]*37e48:.*\[r4, #8\][\s\S]*37e4c:.*\[r4, #10\][\s\S]*37e50:.*\[r4, #11\]",
        "read32_postincrement":r"37e68:.*ldr\s+r3, \[r1\], #4",
        "response_byte0_at_16":r"37e78:.*strb\s+r3, \[r2, #16\]",
        "response_byte1_at_17":r"37e80:.*strb\s+r5, \[r2, #17\]",
        "response_byte2_at_18":r"37e88:.*strb\s+r12, \[r2, #18\]",
        "response_byte3_at_19":r"37e90:.*strb\s+r3, \[r2, #19\]",
        "loop_back":r"37ea4:.*bhi\s+0x37e68",
        "selector1_helper":r"37ee8:.*b\s+0x3872c",
        "selector2_buffer_at_16":r"37f00:.*add\s+r0, r4, #16",
        "selector2_size_256":r"37f08:.*mov\s+r2, #256",
        "selector2_helper":r"37f10:.*b\s+0x38a6c",
    }
    observed={k:bool(re.search(v,text,re.M)) for k,v in anchors.items()}
    missing=[k for k,v in observed.items() if not v]
    return {"anchors":observed,"missing":missing,"all_required_present":not missing}

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf)
    out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    disasm=dispatch.run_objdump(elf,HANDLER_START,HANDLER_END)
    verification=verify_disassembly(disasm)
    report={
        "schema":"wrt8964-mem-addr-access-semantics/v1",
        "firmware_handler":{"command_id":"0x001d","start":"0x00037de8","end":"0x00037f58"},
        "host_layout":{
            "header_size":HEADER_SIZE,
            "address":{"offset":ADDRESS_OFF,"size":4,"encoding":"little-endian"},
            "length":{"offset":LENGTH_OFF,"size":2,"encoding":"little-endian","unit":"32-bit words","max":64},
            "reserved_selector":{"offset":SELECTOR_OFF,"size":2,"encoding":"little-endian"},
            "value":{"offset":VALUES_OFF,"element_size":4,"count":64,"encoding":"little-endian"},
            "source":"kaloz/mwlwifi@db97edf20fadea2617805006f5230665fadc6a8c hif/hostcmd.h"
        },
        "selector_semantics":{
            "0":{
                "status":"observed",
                "behavior":"Read length sequential 32-bit words beginning at address and write them little-endian to response value[] at offset 16.",
                "address_step_bytes":4,
                "length_cap_words":64,
                "rehost_function":"execute_selector0"
            },
            "1":{
                "status":"partially-observed",
                "behavior":"Loads address from +8 and value[0] from +16 then branches to helper 0x0003872c; helper semantics unresolved."
            },
            "2":{
                "status":"partially-observed",
                "behavior":"Loads address from +8, passes response buffer at +16 and size 0x100 to helper 0x00038a6c; helper semantics unresolved."
            },
            "3":{
                "status":"partially-observed",
                "behavior":"Writes two firmware constants into response at +16 and +24; constant meanings unresolved."
            }
        },
        "disassembly_verification":verification,
        "guardrail":"The semantic rehost models selector 0 only. Selectors 1-3 and the optional pre-handler call at 0x000363e4 remain explicit UNKNOWNs until independently recovered.",
    }
    (out/"mem-addr-access-semantics.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    (out/"mem-addr-access-disassembly.txt").write_text(disasm)
    print(json.dumps({"all_required_present":verification["all_required_present"],"missing":verification["missing"]},indent=2))
    return 0 if verification["all_required_present"] else 3

if __name__=="__main__":
    raise SystemExit(main())
