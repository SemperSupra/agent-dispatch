#!/usr/bin/env python3
"""Correlate W8964 vendor-source crypto counter/descriptor contracts with 88W8964 firmware.

The public GPL W8964 source is treated as a semantic donor, not firmware
authority. Promotions require agreement with the pinned 88W8964 binary.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import urllib.request
from pathlib import Path

DONOR_REF="dfb9d765615a748f064dfcfa7e289c43d846a15e"
DONOR_BASE=f"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/{DONOR_REF}"
URLS={
  "hostcmdcommon":f"{DONOR_BASE}/CMIF/include/hostcmdcommon.h",
  "fwcmd":f"{DONOR_BASE}/DRV/wlan-v10/driver/ap8xLnxFwcmd.c",
  "w8964_desc":f"{DONOR_BASE}/DRV/wlan-v10/driver/W8964/ap8xLnxDesc.h",
  "dump":f"{DONOR_BASE}/DRV/wlan-v10/driver/ap8xLnxDump.c",
}
FW_SHA256="ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751"

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

def fetch(url:str)->str:
    req=urllib.request.Request(url,headers={"User-Agent":"SemperSupra-WRT-crypto-counter-contract/1.0"})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")

def has_all(text:str,*xs:str)->bool:
    return all(x in text for x in xs)

def line_at(text:str,addr:int)->str:
    m=re.search(rf"^\s*0*{addr:x}:\s+.*$",text,re.M|re.I)
    return m.group(0).strip() if m else ""

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--elf",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)

    src={k:fetch(v) for k,v in URLS.items()}
    enable=dp.run_objdump(elf,0x28f54,0x29070)
    setkey=dp.run_objdump(elf,0x29114,0x29410)

    donor_checks={
      "legacy_w8964_key_ids":has_all(src["hostcmdcommon"],
        "#define KEY_TYPE_ID_WEP", "0x00",
        "#define KEY_TYPE_ID_TKIP", "0x01",
        "#define KEY_TYPE_ID_AES", "0x02"),
      "tsc_valid_flag_is_sequence_counter_valid":has_all(src["hostcmdcommon"],
        "#define ENCR_KEY_FLAG_TSC_VALID",
        "Sequence counters are valid"),
      "legacy_tkip_counter_shape_u16_u32":re.search(
        r"struct\s+tagENCR_TKIPSEQCNT\s*\{\s*u16\s+low;\s*u32\s+high;",
        src["hostcmdcommon"],re.S) is not None,
      "legacy_tkip_has_rsc_and_tsc":has_all(src["hostcmdcommon"],
        "ENCR_TKIPSEQCNT TkipRsc;",
        "ENCR_TKIPSEQCNT TkipTsc;"),
      "w8964_group_tkip_sends_tsc":has_all(src["fwcmd"],
        "int wlFwSetWpaTkipGroupK(",
        "ENCR_KEY_FLAG_TSC_VALID",
        "TkipTsc.low",
        "TkipTsc.high"),
      "w8964_pairwise_tkip_sends_txiv_as_tsc":has_all(src["fwcmd"],
        "StaInfo_p->keyMgmtStateInfo.TxIV16",
        "StaInfo_p->keyMgmtStateInfo.TxIV32",
        "TkipTsc.low",
        "TkipTsc.high"),
      "w8964_eu_descriptor":has_all(src["w8964_desc"],
        "typedef struct eudesc_t",
        "key_index:14",
        "key_size:2",
        "hdr_start_offset:4",
        "priority:4",
        "op_mode:3",
        "force_bypass:1",
        "mic_size:2",
        "Encryption Unit Descriptor"),
      "w8964_bb_map":has_all(src["dump"],
        "struct register_map w8964_bb",
        '{"BB", 0x000, 0, 0xee9}'),
      "w8964_four_rf_paths":all(x in src["dump"] for x in (
        '{"RF Path A base", 0xa00, 0, 0xff}',
        '{"RF Path B base", 0xb00, 0, 0xff}',
        '{"RF Path C base", 0xc00, 0, 0xff}',
        '{"RF Path D base", 0xd00, 0, 0xff}')),
    }

    binary_checks={
      "enable_interface_counter_reset_low16":
        "2900c:" in enable and "strh" in line_at(enable,0x2900c) and "[r1, #2]" in line_at(enable,0x2900c),
      "enable_interface_counter_reset_high32":
        "29010:" in enable and "str" in line_at(enable,0x29010) and "[r1, #4]" in line_at(enable,0x29010),
      "enable_station_counter_reset_low16":
        "29064:" in enable and "strh" in line_at(enable,0x29064) and "[r0, #2]" in line_at(enable,0x29064),
      "enable_station_counter_reset_high32":
        "29068:" in enable and "str" in line_at(enable,0x29068) and "[r0, #4]" in line_at(enable,0x29068),
      "group_counter_reset_low16":
        "29348:" in setkey and "strh" in line_at(setkey,0x29348) and "[r1, #2]" in line_at(setkey,0x29348),
      "group_counter_reset_high32":
        "2934c:" in setkey and "str" in line_at(setkey,0x2934c) and "[r1, #4]" in line_at(setkey,0x2934c),
      "control_mode_at_plus8":
        "29338:" in setkey and "strb" in line_at(setkey,0x29338) and "[r1, #8]" in line_at(setkey,0x29338),
      "control_pool_anchor_214":
        "#532" in line_at(enable,0x29050) and "#532" in line_at(setkey,0x292d4),
    }

    source_shape={
      "counter_width_bytes":6,
      "counter_split":"u16 low + u32 high",
      "host_semantic_name":"TKIP TSC / sequence counter",
      "host_validity_flag":"ENCR_KEY_FLAG_TSC_VALID",
    }
    binary_shape={
      "control_offsets":"+2 u16, +4 u32",
      "combined_width_bytes":6,
      "reset_sites":["0x2900c/0x29010","0x29064/0x29068","0x29348/0x2934c"],
      "co_resident_mode_field":"+8",
    }

    all_required=all(donor_checks.values()) and all(binary_checks.values())
    classification={
      "status":"strong-candidate" if all_required else "blocked",
      "candidate":"+0x214 slot offsets +2/+4 form a 48-bit per-key encryption sequence-counter state",
      "basis":[
        "exact binary repeatedly clears +2 as u16 and +4 as u32 together when encryption control state is installed/reset",
        "public GPL W8964 vendor source defines the legacy TKIP sequence counter as exactly u16 low + u32 high",
        "the same W8964 source labels ENCR_KEY_FLAG_TSC_VALID as sequence-counters-valid and passes TkipTsc low/high for group and pairwise TKIP",
        "the six-byte state is adjacent to the already accepted encryption mode byte at +8",
      ],
      "promotion_gate":"Do not promote +2/+4 from strong candidate to accepted TSC/PN semantics until a binary reader/incrementer or another exact-source/binary consumer independently establishes use as a transmit packet/sequence counter.",
    }

    donor_inventory={
      "w8964_encryption_unit_descriptor":{
        "key_index_bits":14,"key_size_bits":2,"hdr_start_offset_bits":4,
        "priority_bits":4,"op_mode_bits":3,"force_bypass_bits":1,"mic_size_bits":2,
        "use":"future source donor for tracing firmware TX encryption descriptor construction",
      },
      "w8964_baseband_register_space":{
        "range":"0x000..0xee9",
        "use":"future donor for naming BB-register access only after command/address correlation",
      },
      "w8964_rf_register_spaces":{
        "paths":["A","B","C","D"],
        "bases":["0xa00","0xb00","0xc00","0xd00"],
        "page_families":{
          "A":["0x1100","0x2100","0x3100","0x4100"],
          "B":["0x1200","0x2200","0x3200","0x4200"],
          "C":["0x1300","0x2300","0x3300","0x4300"],
          "D":["0x1400","0x2400","0x3400","0x4400"],
        },
        "use":"future donor for RF access mapping only after exact 88W8964 command/address agreement",
      },
    }

    report={
      "schema":"wrt8964-crypto-counter-contract/v1",
      "firmware_sha256":FW_SHA256,
      "donor":{"repo":"wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO","ref":DONOR_REF,"urls":URLS,
               "provenance":"public GPLv2 NXP/Marvell-derived W8964 driver source; semantic donor, not firmware authority"},
      "donor_checks":donor_checks,
      "binary_checks":binary_checks,
      "source_shape":source_shape,
      "binary_shape":binary_shape,
      "classification":classification,
      "donor_inventory":donor_inventory,
      "focused_binary_lines":{
        f"0x{x:x}":line_at(enable if x<0x29114 else setkey,x)
        for x in (0x2900c,0x29010,0x29050,0x29064,0x29068,0x292d4,0x29338,0x29348,0x2934c)
      },
      "guardrails":[
        "No vendor-source field name is promoted into firmware semantics on resemblance alone.",
        "The +2/+4 sequence-counter identity remains a strong candidate until an independent firmware consumer/increment path closes the gate.",
        "No hardware register ownership is inferred for +0x214.",
        "Firmware bytes remain ephemeral; output is derived JSON/text only.",
      ],
    }
    (out/"crypto-counter-contract.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "donor_checks":donor_checks,
      "binary_checks":binary_checks,
      "classification":classification,
      "donor_inventory":donor_inventory,
    },indent=2,sort_keys=True))
    return 0 if all_required else 3

if __name__=="__main__":
    raise SystemExit(main())
