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
ACTION_HANDLER=0x34D2C
ENABLE_HELPER=0x28F54
REMOVE_HELPER=0x29070
SET_KEY_HELPER=0x29114

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

def verify_action_handler(text:str)->dict[str,Any]:
    anchors={
        "action_type_le32":all(bool(re.search(p,text)) for p in (
            r"34d30:.*ldrb\s+r1, \[r0, #9\]",
            r"34d38:.*ldrb\s+r12, \[r0, #8\]",
            r"34d3c:.*ldrb\s+r3, \[r0, #10\]",
            r"34d40:.*ldrb\s+r4, \[r0, #11\]",
            r"34d54:.*orr\s+r2, r2, r4, lsl #24",
        )),
        "action_low_byte_dispatch":all(bool(re.search(p,text)) for p in (
            r"34d58:.*tst\s+r2, #255",
            r"34d64:.*cmp\s+r1, #1",
            r"34d6c:.*cmp\s+r1, #3",
            r"34d74:.*cmp\s+r1, #2",
        )),
        "remove_key_path":all(bool(re.search(p,text)) for p in (
            r"34d7c:.*ldrb\s+r1, \[r0, #5\]",
            r"34d84:.*add\s+r0, r12, #58",
            r"34d8c:.*b\s+0x29070",
        )),
        "enable_type_byte":bool(re.search(r"34d90:.*ldrb\s+r2, \[r0, #22\]",text)),
        "enable_helper":all(bool(re.search(p,text)) for p in (
            r"34e04:.*ldrb\s+r2, \[r0, #5\]",
            r"34e0c:.*add\s+r0, r0, #16",
            r"34e14:.*b\s+0x28f54",
        )),
        "set_key_path":all(bool(re.search(p,text)) for p in (
            r"34e18:.*ldrb\s+r2, \[r12, #13\]",
            r"34e1c:.*ldrb\s+r1, \[r12, #12\]",
            r"34e38:.*ldrb\s+r4, \[r12, #8\]",
            r"34e50:.*ldrb\s+r3, \[r12, #11\]",
            r"34e70:.*add\s+r1, r12, #14",
            r"34e74:.*add\s+r0, r12, #58",
            r"34e78:.*bl\s+0x29114",
        )),
        "set_group_key_path":all(bool(re.search(p,text)) for p in (
            r"34e84:.*ldrb\s+r1, \[r12, #13\]",
            r"34e9c:.*mov\s+r2, #1",
            r"34edc:.*add\s+r1, r12, #14",
            r"34ee0:.*add\s+r0, r12, #58",
            r"34ee4:.*bl\s+0x29114",
        )),
    }
    return {"anchors":anchors,"all_required_present":all(anchors.values())}

def action_semantics()->dict[str,Any]:
    return {
        "dispatch_field":{"offset":8,"width":4,"effective_selector":"low 8 bits"},
        "actions":{
            "0":{
                "name":"ENABLE_HW_ENCR",
                "action_data_type_offset":22,
                "observed_type_map":{
                    "0":1,"1":0,"2":0,"3":0,"4":3,"5":0,
                    "6":4,"7":4,"8":6,"9":5,"10":7,"11":8,
                    ">=12":0,
                },
                "known_host_values":{"0":"WEP","1":"DISABLE","4":"TKIP","6":"AES","7":"MIX"},
                "helper":"0x00028f54",
                "helper_args":"r0=&mac_addr(command+16), r1=mapped internal encryption mode, r2=macid(command+5)",
            },
            "1":{
                "name":"SET_KEY",
                "helper":"0x00029114",
                "helper_args":"r0=&key_param.mac_addr(+74), r1=&key(+30), r2=key_type_id low8, r3=key_index low8; stack[0]=key_len low8, stack[1]=macid, stack[2]=0",
            },
            "2":{
                "name":"REMOVE_KEY",
                "helper":"0x00029070",
                "helper_args":"r0=&key_param.mac_addr(+74), r1=macid(command+5)",
            },
            "3":{
                "name":"SET_GROUP_KEY",
                "helper":"0x00029114",
                "helper_args":"same as SET_KEY except stack[2]=1",
            },
        },
        "observed_truncation":{
            "key_type_id":"low byte only before helper",
            "key_index":"low byte only before helper",
            "key_len":"low byte only before helper",
        },
    }

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
    descriptor_probe=dispatch.run_objdump(elf,descriptor,min(descriptor+0x500,0x59218)) if descriptor < 0x59218 else ""
    enable_helper=dispatch.run_objdump(elf,ENABLE_HELPER,REMOVE_HELPER)
    remove_helper=dispatch.run_objdump(elf,REMOVE_HELPER,SET_KEY_HELPER)
    set_key_helper=dispatch.run_objdump(elf,SET_KEY_HELPER,0x29500)

    dver=verify_dispatch(dispatcher)
    wver=verify_wrapper(wrapper)
    aver=verify_action_handler(descriptor_probe)
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
        "descriptor_target_probe":summarize_helper(descriptor_probe) if descriptor_probe else {
            "status":"not-in-executable-load-range",
            "descriptor_value":f"0x{descriptor:08x}",
        },
        "action_handler":{
            "address":"0x00034d2c",
            "verification":aver,
            "semantics":action_semantics(),
        },
        "action_helpers":{
            "enable_0x28f54":summarize_helper(enable_helper),
            "remove_0x29070":summarize_helper(remove_helper),
            "set_key_0x29114":summarize_helper(set_key_helper),
        },
        "guardrail":"Action selection and argument marshalling are recovered directly from firmware instructions. Downstream helper semantics are kept separate and remain hypotheses until independently characterized or instruction-level executed under recovered state.",
    }
    (out/"update-encryption-semantics.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    (out/"update-encryption-dispatch.txt").write_text(dispatcher)
    (out/"update-encryption-wrapper.txt").write_text(wrapper)
    (out/"update-encryption-helper-0x21c68.txt").write_text(helper)
    if descriptor_probe:
        (out/"update-encryption-descriptor-target.txt").write_text(descriptor_probe)
    (out/"update-encryption-enable-helper.txt").write_text(enable_helper)
    (out/"update-encryption-remove-helper.txt").write_text(remove_helper)
    (out/"update-encryption-set-key-helper.txt").write_text(set_key_helper)
    print(json.dumps({
        "dispatch":dver,
        "wrapper":wver,
        "descriptor_value":f"0x{descriptor:08x}",
        "helper_calls":report["generic_helper_probe"]["calls"],
        "helper_r1_offsets":report["generic_helper_probe"]["r1_command_buffer_offsets"],
        "helper_compares":report["generic_helper_probe"]["compares"][:40],
        "descriptor_probe_instruction_count":report["descriptor_target_probe"].get("instruction_count"),
        "descriptor_probe_calls":report["descriptor_target_probe"].get("calls",[])[:40],
        "descriptor_probe_compares":report["descriptor_target_probe"].get("compares",[])[:80],
        "descriptor_probe_r1_offsets":report["descriptor_target_probe"].get("r1_command_buffer_offsets",[]),
        "action_handler_verification":aver,
        "action_semantics":report["action_handler"]["semantics"],
        "enable_helper_calls":report["action_helpers"]["enable_0x28f54"]["calls"][:40],
        "remove_helper_calls":report["action_helpers"]["remove_0x29070"]["calls"][:40],
        "set_key_helper_calls":report["action_helpers"]["set_key_0x29114"]["calls"][:80],
    },indent=2,sort_keys=True))
    return 0 if dver["all_required_present"] and wver["all_required_present"] and aver["all_required_present"] else 3

if __name__=="__main__":
    raise SystemExit(main())
