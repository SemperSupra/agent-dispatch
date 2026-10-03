#!/usr/bin/env python3
"""Cloud-only semantic probe for 88W8964 HOSTCMD_CMD_UPDATE_ENCRYPTION (0x1122)."""
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

COMMAND_ID=0x1122
DISPATCH_TARGET=0x37B84
GENERIC_HELPER=0x21C68
DESCRIPTOR_LITERAL=0x38394

HOST_LAYOUT={
    "command_id":"0x1122",
    "enable_form":{
        "action_type":{"offset":8,"size":4},
        "data_length":{"offset":12,"size":4},
        "mac_addr":{"offset":16,"size":6},
        "action_data":{"offset":22,"size":"variable"},
    },
    "set_key_form":{
        "action_type":{"offset":8,"size":4},
        "data_length":{"offset":12,"size":4},
        "key_param":{
            "offset":16,
            "length":{"offset":16,"size":2},
            "key_type_id":{"offset":18,"size":2},
            "key_info":{"offset":20,"size":4},
            "key_index":{"offset":24,"size":4},
            "key_len":{"offset":28,"size":2},
            "key_union":{"offset":30,"size":44},
            "mac_addr":{"offset":74,"size":6},
        },
        "packed_size":80,
    },
    "action_type":{
        "0":"ENABLE_HW_ENCR",
        "1":"SET_KEY",
        "2":"REMOVE_KEY",
        "3":"SET_GROUP_KEY",
    },
    "key_type_id":{"0":"WEP","1":"TKIP","2":"AES-CCMP"},
    "source":"kaloz/mwlwifi@db97edf20fadea2617805006f5230665fadc6a8c hif/hostcmd.h + hif/fwcmd.c",
}

def read_elf_u32(elf:Path,address:int)->int:
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

def verify_dispatch(text:str)->dict[str,Any]:
    anchors={
        "base_0x1101":bool(re.search(r"364d8:.*movw\s+lr, #4353.*0x1101",text)),
        "subtract_base":bool(re.search(r"364e0:.*sub\s+r2, r12, lr",text)),
        "delta_0x21":bool(re.search(r"36638:.*cmp\s+r2, #33",text)),
        "branch_0x37b84":bool(re.search(r"3663c:.*beq\s+0x37b84",text)),
    }
    return {"anchors":anchors,"all_required_present":all(anchors.values())}

def verify_wrapper(text:str)->dict[str,Any]:
    anchors={
        "descriptor_load":bool(re.search(r"37b84:.*ldr\s+r0, \[pc, #2056\].*0x38394",text)),
        "command_buffer_r1":bool(re.search(r"37b88:.*mov\s+r1, r4",text)),
        "generic_helper_call":bool(re.search(r"37b8c:.*bl\s+0x21c68",text)),
        "wrapper_exit":bool(re.search(r"37b90:.*b\s+0x38e54",text)),
    }
    return {"anchors":anchors,"all_required_present":all(anchors.values())}

def summarize_helper(text:str)->dict[str,Any]:
    insns=dispatch.parse_instructions(text)
    calls=[]
    branches=[]
    compares=[]
    r1_offsets=[]
    r0_offsets=[]
    for ins in insns:
        mnem=ins["mnemonic"]
        ops=ins["operands"]
        if mnem=="bl":
            target=dispatch.branch_target(ins)
            if target is not None:
                calls.append({"address":ins["address"],"target":target,"text":ins["text"]})
        elif mnem.startswith("b"):
            target=dispatch.branch_target(ins)
            if target is not None:
                branches.append({"address":ins["address"],"mnemonic":mnem,"target":target,"text":ins["text"]})
        if mnem in {"cmp","cmn","tst","teq"}:
            compares.append(ins["text"])
        for reg,acc in (("r1",r1_offsets),("r0",r0_offsets)):
            for m in re.finditer(r"\["+reg+r", #([0-9]+)\]",ops):
                acc.append(int(m.group(1)))
    return {
        "instruction_count":len(insns),
        "calls":calls[:100],
        "branches":branches[:200],
        "compares":compares[:200],
        "r1_command_buffer_offsets":sorted(set(r1_offsets)),
        "r0_base_offsets":sorted(set(r0_offsets)),
        "instructions":insns[:1200],
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)

    dispatcher=dispatch.run_objdump(elf,0x364c0,0x36650)
    wrapper=dispatch.run_objdump(elf,0x37b84,0x37b94)
    helper=dispatch.run_objdump(elf,GENERIC_HELPER,0x21f80)
    descriptor=read_elf_u32(elf,DESCRIPTOR_LITERAL)

    dver=verify_dispatch(dispatcher)
    wver=verify_wrapper(wrapper)
    report={
        "schema":"wrt8964-update-encryption-semantics/v1",
        "firmware_sha256":"ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751",
        "host_contract":HOST_LAYOUT,
        "firmware_dispatch":{
            "command_id":"0x1122",
            "derivation":"0x1122 - 0x1101 = 0x21; dispatcher compares delta r2 against 33 then branches",
            "target":"0x00037b84",
            "verification":dver,
        },
        "wrapper":{
            "address":"0x00037b84",
            "generic_helper":"0x00021c68",
            "descriptor_literal_address":"0x00038394",
            "descriptor_value":f"0x{descriptor:08x}",
            "verification":wver,
        },
        "generic_helper_probe":summarize_helper(helper),
        "guardrail":"This pass proves routing into the generic helper and records field-access/control-flow evidence. It does not yet assign crypto semantics to helper state or hardware-facing calls.",
    }
    (out/"update-encryption-semantics.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    (out/"update-encryption-dispatch.txt").write_text(dispatcher)
    (out/"update-encryption-wrapper.txt").write_text(wrapper)
    (out/"update-encryption-helper-0x21c68.txt").write_text(helper)
    print(json.dumps({
        "dispatch":dver,
        "wrapper":wver,
        "descriptor_value":f"0x{descriptor:08x}",
        "helper_calls":report["generic_helper_probe"]["calls"],
        "helper_r1_offsets":report["generic_helper_probe"]["r1_command_buffer_offsets"],
        "helper_compares":report["generic_helper_probe"]["compares"][:40],
    },indent=2,sort_keys=True))
    return 0 if dver["all_required_present"] and wver["all_required_present"] else 3

if __name__=="__main__":
    raise SystemExit(main())
