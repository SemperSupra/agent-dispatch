#!/usr/bin/env python3
"""Recover the W8964 UPDATE_ENCRYPTION host-side contract from open source.

This lane deliberately distinguishes:
- exact current mwlwifi host ABI/implementation;
- NXP/Marvell W8964-specific host-driver behavior in the non-W906X branch;
- firmware semantics, which require separate binary evidence.
"""
from __future__ import annotations
import argparse, hashlib, json, re, urllib.request
from pathlib import Path

REF="dfb9d765615a748f064dfcfa7e289c43d846a15e"
MWL_REF="db97edf20fadea2617805006f5230665fadc6a8c"
BASE="https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/"+REF+"/"
SOURCES={
 "nxp_hostcmdcommon": BASE+"CMIF/include/hostcmdcommon.h",
 "nxp_w8964_fwcmd": BASE+"DRV/wlan-v10/driver/ap8xLnxFwcmd.c",
 "nxp_keymgmt_ap": BASE+"DRV/wlan-v10/core/encr/AP/keyMgmt.c",
 "mwlwifi_hostcmd": f"https://raw.githubusercontent.com/kaloz/mwlwifi/{MWL_REF}/hif/hostcmd.h",
 "mwlwifi_fwcmd": f"https://raw.githubusercontent.com/kaloz/mwlwifi/{MWL_REF}/hif/fwcmd.c",
}
UA="SemperSupra-WRT3200ACM-W8964-contract/1.0"

def get(url:str)->bytes:
    req=urllib.request.Request(url,headers={"User-Agent":UA})
    with urllib.request.urlopen(req,timeout=45) as r:return r.read()

def require(text:str, patterns:list[str], label:str)->dict:
    found={}
    for p in patterns:
        m=re.search(p,text,re.S|re.M)
        found[p]=bool(m)
    if not all(found.values()):
        raise RuntimeError(f"{label}: required source anchors missing: {[k for k,v in found.items() if not v]}")
    return found

def macro(text:str,name:str):
    m=re.search(r"^\s*#define\s+"+re.escape(name)+r"\s+([^/\n]+)",text,re.M)
    return m.group(1).strip() if m else None

def legacy_w8964_crypto_block(text:str)->str:
    # hostcmdcommon.h carries two crypto ABI families in one conditional.
    # Anchor on the legacy branch's distinctive WEP=0 definition instead of
    # selecting the first nested #else after the W906X #if.
    anchor=re.search(r"^\\s*#define\\s+KEY_TYPE_ID_WEP\\s+0x00\\b",text,re.M)
    if not anchor:
        raise RuntimeError("legacy W8964 KEY_TYPE_ID_WEP=0 anchor not found")
    start=text.rfind("#else",0,anchor.start())
    end=text.find("#endif /* SOC_W906X */",anchor.end())
    if start<0 or end<0:
        raise RuntimeError("legacy W8964 crypto block boundaries not found")
    block=text[start:end]
    required={
        "WEP":"0x00","TKIP":"0x01","AES":"0x02",
        "PAIRWISE":"0x00000008","TSC":"0x00000040",
        "WEP_TX":"0x01000000","MIC":"0x02000000",
    }
    probes={
        "WEP":macro(block,"KEY_TYPE_ID_WEP"),
        "TKIP":macro(block,"KEY_TYPE_ID_TKIP"),
        "AES":macro(block,"KEY_TYPE_ID_AES"),
        "PAIRWISE":macro(block,"ENCR_KEY_FLAG_PAIRWISE"),
        "TSC":macro(block,"ENCR_KEY_FLAG_TSC_VALID"),
        "WEP_TX":macro(block,"ENCR_KEY_FLAG_WEP_TXKEY"),
        "MIC":macro(block,"ENCR_KEY_FLAG_MICKEY_VALID"),
    }
    if probes!=required:
        raise RuntimeError(f"legacy W8964 crypto block validation failed: {probes}")
    return block

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);ns=ap.parse_args()
    raw={k:get(v) for k,v in SOURCES.items()}
    txt={k:v.decode("utf-8","replace") for k,v in raw.items()}
    h=txt["nxp_hostcmdcommon"]; c=txt["nxp_w8964_fwcmd"]; mh=txt["mwlwifi_hostcmd"]; mf=txt["mwlwifi_fwcmd"]
    h_w8964=legacy_w8964_crypto_block(h)

    # W8964-specific host-driver path is the !SOC_W906X branch in this source family.
    anchors={}
    anchors["tkip_enable"]=require(c,[
      r"#ifndef\s+SOC_W906X\s+int\s+wlFwSetWpaTkipMode\b",
      r"ActionType\s*=\s*ENDIAN_SWAP32\(EncrActionEnableHWEncryption\)",
      r"ActionData\[0\]\s*=\s*EncrTypeTkip",
      r"wlexecuteCommand\([^;]*HostCmd_CMD_UPDATE_ENCRYPTION\)",
    ],"W8964 TKIP enable")
    anchors["aes_enable"]=require(c,[
      r"#ifndef\s+SOC_W906X\s+int\s+wlFwSetWpaAesMode\b",
      r"ActionData\[0\]\s*=\s*keymgmt_aesModeGet\(ouiType\)",
    ],"W8964 AES enable")
    anchors["pairwise_key"]=require(c,[
      r"ActionType\s*=\s*ENDIAN_SWAP32\(EncrActionTypeSetKey\)",
      r"KeyTypeId\s*=\s*ENDIAN_SWAP16\(KEY_TYPE_ID_TKIP\)",
      r"KeyInfo\s*=\s*ENDIAN_SWAP32\(ENCR_KEY_FLAG_PAIRWISE\s*\|\s*ENCR_KEY_FLAG_TSC_VALID\s*\|\s*ENCR_KEY_FLAG_MICKEY_VALID\)",
      r"KeyLen\s*=\s*ENDIAN_SWAP16\(sizeof\(TKIP_TYPE_KEY\)\)",
    ],"W8964 pairwise TKIP")
    anchors["aes_pairwise"]=require(c,[
      r"KeyTypeId\s*=\s*ENDIAN_SWAP16\(keyTypeId\)",
      r"KeyInfo\s*=\s*ENDIAN_SWAP32\(ENCR_KEY_FLAG_PAIRWISE\)",
      r"Key\.AesKey\.KeyMaterial",
    ],"W8964 pairwise AES")
    anchors["group_key"]=require(c,[
      r"ActionType\s*=\s*ENDIAN_SWAP32\(EncrActionTypeSetGroupKey\)",
      r"KeyInfo\s*=\s*ENDIAN_SWAP32\(ENCR_KEY_FLAG_TXGROUPKEY",
    ],"W8964 group key")
    anchors["remove_key"]=require(c,[
      r"ActionType\s*=\s*ENDIAN_SWAP32\(EncrActionTypeRemoveKey\)",
      r"ENCR_KEY_FLAG_RXGROUPKEY\s*\|\s*\n?\s*ENCR_KEY_FLAG_TXGROUPKEY",
    ],"W8964 remove key")
    anchors["mwlwifi_pairwise"]=require(mf,[
      r"IEEE80211_KEY_FLAG_PAIRWISE",
      r"ENCR_KEY_FLAG_PAIRWISE",
      r"KEY_TYPE_ID_TKIP",
      r"KEY_TYPE_ID_AES",
    ],"mwlwifi crypto")

    defs={}
    for name in [
      "KEY_TYPE_ID_WEP","KEY_TYPE_ID_TKIP","KEY_TYPE_ID_AES","KEY_TYPE_ID_CCMP",
      "ENCR_KEY_FLAG_RXGROUPKEY","ENCR_KEY_FLAG_TXGROUPKEY","ENCR_KEY_FLAG_PAIRWISE",
      "ENCR_KEY_FLAG_AUTHENTICATOR","ENCR_KEY_FLAG_TSC_VALID",
      "ENCR_KEY_FLAG_WEP_TXKEY","ENCR_KEY_FLAG_MICKEY_VALID"
    ]:
        defs[name]={"nxp_w8964_non_w906x":macro(h_w8964,name),"mwlwifi":macro(mh,name)}

    # Structure offsets are already independently exercised by the firmware rehost.
    layout={
      "host_header":0,
      "action_type":8,
      "data_length":12,
      "key_param":16,
      "key_param.length":16,
      "key_param.key_type_id":18,
      "key_param.key_info":20,
      "key_param.key_index":24,
      "key_param.key_len":28,
      "key_param.key_union":30,
      "key_param.mac_addr":74,
      "packed_set_key_size":80,
    }
    report={
      "schema":"wrt8964-crypto-host-source-contract/v1",
      "source_digests":{k:hashlib.sha256(v).hexdigest() for k,v in raw.items()},
      "source_classes":{
        "nxp_hostcmdcommon":"Marvell/NXP host interface source; values reported here are explicitly extracted from the non-SOC_W906X/SOC_W9068 legacy block used by W8964-family builds",
        "nxp_w8964_fwcmd":"Marvell/NXP host-driver implementation containing the non-SOC_W906X path used by W8964-family builds",
        "mwlwifi_hostcmd":"exact current open host ABI for the pinned 88W8964 blob",
        "mwlwifi_fwcmd":"exact current open host implementation for the pinned 88W8964 blob",
      },
      "anchors":anchors,
      "key_definitions":defs,
      "command_layout":layout,
      "conditional_selection":{
        "nxp_hostcmdcommon":"non-SOC_W906X/SOC_W9068 legacy branch",
        "reason":"The same header contains newer W906X definitions with different numeric key IDs/flags; selecting the first textual define is incorrect for W8964."
      },
      "source_semantics":{
        "enable_hardware_encryption":"Action 0; W8964 host source sends EncrTypeTkip for TKIP and keymgmt_aesModeGet(ouiType) for AES-family modes.",
        "set_pairwise_key":"Action 1; TKIP uses type 1 plus pairwise/TSC/MIC-valid flags; AES-family uses the AES-family key type plus pairwise flag.",
        "remove_key":"Action 2; W8964 group-clean path supplies RXGROUPKEY|TXGROUPKEY.",
        "set_group_key":"Action 3; W8964 TKIP/AES group-key paths use the group action and group-key flags.",
      },
      "promotion_rule":"These are host-side contract/behavior facts. A firmware-side semantic is promoted only where recovered 88W8964 instructions consume the corresponding field or reproduce the behavior."
    }
    Path(ns.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"all_source_anchors":all(all(x.values()) for x in anchors.values()),"definitions":defs,"layout":layout},indent=2,sort_keys=True))
    return 0
if __name__=="__main__":raise SystemExit(main())
