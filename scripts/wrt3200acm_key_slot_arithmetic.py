#!/usr/bin/env python3
"""Recover the +0xd8/+0x214 encryption slot arithmetic without naming hardware state."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import struct
import urllib.request
from pathlib import Path

REF="db97edf20fadea2617805006f5230665fadc6a8c"
BASE=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{REF}"
URLS={
  "hostcmd":f"{BASE}/hif/hostcmd.h",
  "fwcmd":f"{BASE}/hif/fwcmd.c",
  "mac80211":f"{BASE}/mac80211.c",
}

P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)


def fetch(url:str)->str:
    req=urllib.request.Request(url,headers={"User-Agent":"SemperSupra-WRT-key-slot-arithmetic/1.0"})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")


def line_at(text:str,address:int)->str:
    m=re.search(rf"^\s*0*{address:x}:\s+.*$",text,re.M|re.I)
    return m.group(0).strip() if m else ""


def line_has(text:str,address:int,*needles:str)->bool:
    line=line_at(text,address).lower()
    return bool(line) and all(n.lower() in line for n in needles)


def read_u32(path:Path,address:int)->int:
    d=path.read_bytes()
    ph=struct.unpack_from("<I",d,28)[0]
    pe=struct.unpack_from("<H",d,42)[0]
    pn=struct.unpack_from("<H",d,44)[0]
    for i in range(pn):
        o=ph+i*pe
        typ,fo,va,_pa,fs,_ms,_fl,_al=struct.unpack_from("<IIIIIIII",d,o)
        if typ==1 and va<=address and address+4<=va+fs:
            return struct.unpack_from("<I",d,fo+address-va)[0]
    raise ValueError(hex(address))


def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)

    hostcmd=fetch(URLS["hostcmd"])
    fwcmd=fetch(URLS["fwcmd"])
    mac=fetch(URLS["mac80211"])
    helper=dp.run_objdump(elf,0x29114,0x29410)

    source_checks={
      "key_types_exact": all(x in hostcmd for x in (
        "#define KEY_TYPE_ID_WEP                         0x00",
        "#define KEY_TYPE_ID_TKIP                        0x01",
        "#define KEY_TYPE_ID_AES",
      )),
      "key_index_documented_wep_only": "For WEP only - actual key index" in hostcmd,
      "wep_forces_set_key_action": all(x in fwcmd for x in (
        "case WLAN_CIPHER_SUITE_WEP40:",
        "case WLAN_CIPHER_SUITE_WEP104:",
        "action = ENCR_ACTION_TYPE_SET_KEY;",
      )),
      "tkip_copy_length_32": all(x in fwcmd for x in (
        "keymlen = MAX_ENCR_KEY_LENGTH + 2 * MIC_KEY_LENGTH;",
        "#include",
      )) and "MAX_ENCR_KEY_LENGTH                     16" in hostcmd and "MIC_KEY_LENGTH                          8" in hostcmd,
      "ccmp_uses_host_keylen": "case WLAN_CIPHER_SUITE_CCMP:\n\t\tkeymlen = key->keylen;" in fwcmd,
      "pairwise_vs_group_action": all(x in fwcmd for x in (
        "if (key->flags & IEEE80211_KEY_FLAG_PAIRWISE)",
        "action = ENCR_ACTION_TYPE_SET_KEY;",
        "action = ENCR_ACTION_TYPE_SET_GROUP_KEY;",
      )),
      "tkip_pairwise_or_group_flags": all(x in fwcmd for x in (
        "KEY_TYPE_ID_TKIP",
        "ENCR_KEY_FLAG_PAIRWISE",
        "ENCR_KEY_FLAG_TXGROUPKEY",
        "ENCR_KEY_FLAG_MICKEY_VALID",
        "ENCR_KEY_FLAG_TSC_VALID",
      )),
      "aes_pairwise_or_group_flags": all(x in fwcmd for x in (
        "KEY_TYPE_ID_AES",
        "ENCR_KEY_FLAG_PAIRWISE",
        "ENCR_KEY_FLAG_TXGROUPKEY",
      )),
      "stnid_zero_is_allocation_failure": all(x in mac for x in (
        "stnid = utils_assign_stnid(priv, mwl_vif->macid, sta->aid);",
        "if (!stnid)",
        "return -EPERM;",
      )),
    }

    helper_ins=dp.parse_instructions(helper)
    flag_writers={"movs","adds","subs","ands","bics","cmp","cmn","tst","teq"}
    between_keytype_and_branch=[
      x for x in helper_ins
      if 0x29124 <= x["address"] <= 0x29154 and x["mnemonic"] in flag_writers
    ]

    binary_checks={
      "helper_decodes_key_index": line_has(helper,0x29118,"mov","r5","r3"),
      "helper_decodes_key_type": line_has(helper,0x29120,"movs","r7","r2"),
      "key_type_zero_flags_reach_indexed_branch": (
        line_has(helper,0x29120,"movs","r7","r2")
        and not between_keytype_and_branch
        and line_has(helper,0x29158,"beq","29168")
      ),
      "helper_decodes_macid": line_has(helper,0x29124,"ldr","r6","[sp, #60]"),
      "helper_decodes_group_flag": line_has(helper,0x29128,"ldr","r9","[sp, #64]"),
      "helper_decodes_key_len": line_has(helper,0x29130,"ldr","r11","[sp, #56]"),
      "tkip_type1_forces_32_bytes": line_has(helper,0x29270,"cmp","r7","#1") and line_has(helper,0x29274,"moveq","r11","#32"),
      "group_flag_branches_away_from_pairwise": line_has(helper,0x29278,"cmp","r9","#0") and line_has(helper,0x2927c,"beq","29398"),
      "indexed_path_key_index_le3": line_has(helper,0x29168,"cmp","r5","#3"),
      "indexed_path_4macid_plus_keyindex": line_has(helper,0x2916c,"add","r6","r5","r6, lsl #2"),
      "indexed_control_slot_stride32": line_has(helper,0x291c8,"ldr","r2","[r4, #532]") and line_has(helper,0x291cc,"add","r0","r2","r6, lsl #5"),
      "indexed_key_slot_stride32": line_has(helper,0x291e8,"ldr","r0","[r4, #216]") and line_has(helper,0x291f4,"add","r0","r0","r6, lsl #5"),
      "group_path_macid_stride128": line_has(helper,0x29288,"ldr","r0","[r4, #216]") and line_has(helper,0x29294,"add","r0","r0","r6, lsl #7"),
      "group_station16_special_case": line_has(helper,0x29280,"cmp","r6","#16") and line_has(helper,0x29284,"beq","292c0"),
      "station16_control_base_0x800": line_has(helper,0x292d4,"ldr","r1","[r4, #532]") and line_has(helper,0x292dc,"add","r1","r1","#2048"),
      "station16_control_mode_at_plus8": line_has(helper,0x29338,"strb","r2","[r1, #8]"),
      "station16_key_base_128macid": line_has(helper,0x2937c,"ldr","r0","[r4, #216]") and line_has(helper,0x2938c,"add","r0","r0","r6, lsl #7"),
      "pairwise_station_lookup": line_has(helper,0x293a0,"bl","3fb34"),
      "pairwise_reads_stnid": line_has(helper,0x293b0,"ldrh","r2","[r5, #24]"),
      "pairwise_base_0x860": line_has(helper,0x293b4,"mov","r0","#2144") and line_has(helper,0x293b8,"add","r0","r0","r2, lsl #5"),
      "pairwise_memcpy": line_has(helper,0x293c8,"bl","44148"),
    }

    table={
      "key_type_0_target":read_u32(elf,0x292f0),
      "key_type_1_target":read_u32(elf,0x292f4),
      "key_type_2_target":read_u32(elf,0x292f8),
    }
    table_checks={
      "key_type0_targets_mode9": table["key_type_0_target"]==0x29334 and line_has(helper,0x29334,"mov","r2","#9"),
      "key_type1_targets_mode3": table["key_type_1_target"]==0x2930c and line_has(helper,0x2930c,"mov","r2","#3"),
      "key_type2_targets_mode4": table["key_type_2_target"]==0x29314 and line_has(helper,0x29314,"mov","r2","#4"),
    }

    stride=32
    macid_count=17
    per_macid_lanes=4
    group_partition_bytes=macid_count*per_macid_lanes*stride
    pairwise_base=0x860
    min_valid_stnid=1
    pairwise_first_effective=pairwise_base+min_valid_stnid*stride
    arithmetic_checks={
      "four_slots_per_macid": per_macid_lanes*stride==128,
      "seventeen_macids_times_four_slots_is_0x880": group_partition_bytes==0x880,
      "station16_group_base_is_0x800": 16*128==0x800,
      "station16_group_block_ends_at_0x880": 16*128+4*32==0x880,
      "pairwise_formula_base_is_slot67": pairwise_base//32==67,
      "nonzero_stnid_moves_first_effective_pairwise_slot_to_0x880": pairwise_first_effective==0x880,
      "group_and_effective_pairwise_partitions_are_adjacent": group_partition_bytes==pairwise_first_effective,
    }

    accepted_group_modes={
      "TKIP":{"key_type":1,"mode":3,"basis":"exact host source can issue SET_GROUP_KEY for TKIP and binary table key_type 1 -> mode 3"},
      "AES_CCMP":{"key_type":2,"mode":4,"basis":"exact host source can issue SET_GROUP_KEY for CCMP and binary table key_type 2 -> mode 4"},
    }

    all_checks={**source_checks,**binary_checks,**table_checks,**arithmetic_checks}
    accepted=all(all_checks.values())
    report={
      "schema":"wrt8964-encryption-slot-arithmetic/v1",
      "firmware_sha256":"ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751",
      "source_ref":REF,
      "source_urls":URLS,
      "source_checks":source_checks,
      "binary_checks":binary_checks,
      "mode_table_words":{k:f"0x{v:08x}" for k,v in table.items()},
      "mode_table_checks":table_checks,
      "arithmetic_checks":arithmetic_checks,
      "promotion":{
        "status":"accepted" if accepted else "blocked",
        "key_material_store_0xd8":{
          "wep_default_key_partition":"offset 0x000..0x87f = 17 MACIDs x 4 WEP/default-key lanes per MACID x 32 bytes; key_type 0 sets Z at 0x29120 and the unchanged flags drive BEQ 0x29158 into this path, which addresses 32*(4*macid+key_index), key_index <=3",
          "group_key_base":"offset 128*macid; exact host SET_GROUP_KEY path is used for TKIP/AES, while WEP is forced to SET_KEY",
          "pairwise_station":"offset 0x860 + 32*stn_id; exact host stn_id=0 is allocation failure, so first effective pairwise slot is 0x880",
          "copy_lengths":"TKIP is forced to 32 bytes in binary and exact source; CCMP uses host key length (normally 16, bounded by source ABI); WEP uses host key length",
        },
        "control_state_0x214":{
          "wep_indexed_path":"key_type 0 (WEP in exact host ABI) selects the 32*(4*macid+key_index) branch; the same arithmetic is observed in +0x214 control state",
          "station16_group_slot":"offset 0x800 = 128*16; mode byte is written at +8",
          "accepted_group_modes":accepted_group_modes,
          "wep_mode9_guardrail":"binary key_type 0 would select mode 9 in the station16 group branch, but exact host source forces WEP to SET_KEY, so mode 9 is not promoted as a reachable WEP group semantic",
        },
        "structural_partition":"The first 0x880 bytes form a 17-MACID x four-32-byte-lane partition. The effective per-station pairwise region begins immediately at 0x880 because the pairwise formula is 0x860+32*stn_id and exact host station IDs are nonzero.",
      },
      "guarded_unknowns":[
        "The key_type-zero branch is now identified as WEP/default-key handling from exact flag provenance plus the pinned host ABI; downstream hardware ownership remains unknown.",
        "The complete +0x214 control record field layout beyond observed mode/reset fields remains unknown.",
        "No hardware descriptor/register ownership is inferred.",
        "Capacity beyond the proven 0x880 partition boundary is not assigned a maximum station-count semantic from size alone."
      ],
      "evidence":{
        "helper_range":"0x29114..0x29410",
        "focused_lines":{f"{pc:x}":line_at(helper,pc) for pc in (
          0x29118,0x29120,0x29124,0x29128,0x29130,0x29150,0x29154,0x29158,0x29168,0x2916c,0x291c8,0x291cc,0x291e8,0x291f4,
          0x29270,0x29274,0x29278,0x2927c,0x29280,0x29284,0x29288,0x29294,0x292d4,0x292dc,0x2930c,
          0x29314,0x29334,0x29338,0x2937c,0x2938c,0x29398,0x293a0,0x293ac,0x293b0,0x293b4,0x293b8,0x293c8
        )}
      }
    }
    (out/"encryption-slot-arithmetic.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "source_checks":source_checks,
      "binary_checks":binary_checks,
      "mode_table_checks":table_checks,
      "arithmetic_checks":arithmetic_checks,
      "promotion":report["promotion"],
    },indent=2,sort_keys=True))
    return 0 if accepted else 3

if __name__=="__main__":
    raise SystemExit(main())
