#!/usr/bin/env python3
"""Qualify WEP40/WEP104 control-mode semantics in the W8964 indexed key path."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import urllib.request
from pathlib import Path

REF="db97edf20fadea2617805006f5230665fadc6a8c"
BASE=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{REF}"
URLS={
  "hostcmd":f"{BASE}/hif/hostcmd.h",
  "fwcmd":f"{BASE}/hif/fwcmd.c",
  "core_h":f"{BASE}/core.h",
  "dev_h":f"{BASE}/hif/pcie/dev.h",
}
P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

def fetch(url:str)->str:
    req=urllib.request.Request(url,headers={"User-Agent":"SemperSupra-WRT-wep-control-mode/1.0"})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")

def line_at(text:str,address:int)->str:
    m=re.search(rf"^\s*0*{address:x}:\s+.*$",text,re.M|re.I)
    return m.group(0).strip() if m else ""

def line_has(text:str,address:int,*needles:str)->bool:
    line=line_at(text,address).lower()
    return bool(line) and all(n.lower() in line for n in needles)

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)

    hostcmd=fetch(URLS["hostcmd"])
    fwcmd=fetch(URLS["fwcmd"])
    core_h=fetch(URLS["core_h"])
    dev_h=fetch(URLS["dev_h"])
    helper=dp.run_objdump(elf,0x29114,0x29210)

    source_checks={
      "host_key_type0_is_wep":"#define KEY_TYPE_ID_WEP                         0x00" in hostcmd,
      "host_key_index_is_wep_only":"For WEP only - actual key index" in hostcmd,
      "four_saved_wep_keys":"#define NUM_WEP_KEYS                  4" in core_h,
      "wep40_cipher_supported":"WLAN_CIPHER_SUITE_WEP40" in fwcmd,
      "wep104_cipher_supported":"WLAN_CIPHER_SUITE_WEP104" in fwcmd,
      "wep_keylen_passed_through":"cmd->key_param.key_len = cpu_to_le16(key->keylen);" in fwcmd,
      "wep_forces_set_key":"action = ENCR_ACTION_TYPE_SET_KEY;" in fwcmd,
      "wep40_exact_material_bits":"KEY_TYPE_WEP40,     /* WEP with  40 bit key + 24 bit IV =  64 */" in dev_h,
      "wep104_exact_material_bits":"KEY_TYPE_WEP104,    /* WEP with 104 bit key + 24 bit IV = 128 */" in dev_h,
    }

    source_derived={
      "wep40_key_bytes":40//8,
      "wep104_key_bytes":(104+7)//8,
      "four_default_key_indices":4,
    }

    flag_writers={"movs","adds","subs","ands","bics","cmp","cmn","tst","teq"}
    ins=dp.parse_instructions(helper)
    intervening=[
      x["text"] for x in ins
      if 0x29124 <= x["address"] <= 0x29154 and x["mnemonic"] in flag_writers
    ]

    binary_checks={
      "key_type_movs_sets_wep_zero_flag":line_has(helper,0x29120,"movs","r7","r2"),
      "no_flag_writer_before_wep_beq":not intervening,
      "wep_beq_to_indexed_path":line_has(helper,0x29158,"beq","29168"),
      "wep_key_index_bound_0_to3":line_has(helper,0x29168,"cmp","r5","#3") and line_has(helper,0x29170,"bhi","2923c"),
      "wep_slot_index_4macid_plus_keyindex":line_has(helper,0x2916c,"add","r6","r5","r6, lsl #2"),
      "control_slot_from_anchor214_stride32":line_has(helper,0x291c8,"ldr","r2","[r4, #532]") and line_has(helper,0x291cc,"add","r0","r2","r6, lsl #5"),
      "key_len_compare_5":line_has(helper,0x291c4,"cmp","r11","#5"),
      "wep40_mode1":line_has(helper,0x291dc,"moveq","r1","#1"),
      "wep104_mode2_fallback":line_has(helper,0x291e0,"movne","r1","#2"),
      "mode_stored_at_control_plus8":line_has(helper,0x291e4,"strb","r1","[r0, #8]"),
      "key_slot_from_anchor_d8_stride32":line_has(helper,0x291e8,"ldr","r0","[r4, #216]") and line_has(helper,0x291f4,"add","r0","r0","r6, lsl #5"),
      "key_bytes_copied_by_memcpy_veneer":line_has(helper,0x291fc,"b","44148"),
    }

    semantic_checks={
      "wep40_exactly_hits_eq5":source_derived["wep40_key_bytes"]==5,
      "wep104_exactly_hits_ne5":source_derived["wep104_key_bytes"]==13 and source_derived["wep104_key_bytes"]!=5,
      "binary_index_count_matches_source_saved_key_count":4==source_derived["four_default_key_indices"],
    }

    all_checks={**source_checks,**binary_checks,**semantic_checks}
    accepted=all(all_checks.values())
    report={
      "schema":"wrt8964-wep-control-mode/v1",
      "firmware_sha256":"ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751",
      "source_ref":REF,
      "source_urls":URLS,
      "source_checks":source_checks,
      "source_derived":source_derived,
      "binary_checks":binary_checks,
      "semantic_checks":semantic_checks,
      "promotion":{
        "status":"accepted" if accepted else "blocked",
        "indexed_wep_slot":"slot = 4*macid + key_index, key_index 0..3; +0xd8 key material and +0x214 control state use parallel 32-byte slots",
        "wep40_control_mode":{"key_material_bytes":5,"control_plus8":1},
        "wep104_control_mode":{"key_material_bytes":13,"control_plus8":2},
        "basis":"Exact mwlwifi source defines key_type0=WEP, four WEP keys, WEP40=40-bit material and WEP104=104-bit material, and passes key->keylen. Firmware selects the indexed path from key_type0, compares key_len to 5, stores mode1 on equality and mode2 otherwise.",
        "semantic_limit":"Values 1 and 2 are accepted as firmware WEP40/WEP104 control-state mode values at +0x214 slot +8. They are not labeled as hardware cipher/register encodings without independent hardware-facing evidence."
      },
      "guarded_unknowns":[
        "Fields +2/+4 and other fields in the WEP +0x214 32-byte control record remain only structurally observed unless separately recovered.",
        "Hardware ownership/programming downstream of the software control record remains UNKNOWN."
      ],
      "evidence":{
        "helper_range":"0x29114..0x29210",
        "focused_lines":{f"{pc:x}":line_at(helper,pc) for pc in (
          0x29120,0x29158,0x29168,0x2916c,0x29170,0x291c4,0x291c8,0x291cc,
          0x291dc,0x291e0,0x291e4,0x291e8,0x291f4,0x291fc
        )},
        "intervening_flag_writers":intervening
      }
    }
    (out/"wep-control-mode.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "source_checks":source_checks,
      "source_derived":source_derived,
      "binary_checks":binary_checks,
      "semantic_checks":semantic_checks,
      "promotion":report["promotion"]
    },indent=2,sort_keys=True))
    return 0 if accepted else 3

if __name__=="__main__":
    raise SystemExit(main())
