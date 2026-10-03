#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re, urllib.request
from pathlib import Path

UA="SemperSupra-WRT3200ACM-source-oracle/1.0"
SOURCES=[
  {
    "id":"mwlwifi-hostcmd",
    "class":"exact-host-abi",
    "url":"https://raw.githubusercontent.com/kaloz/mwlwifi/db97edf20fadea2617805006f5230665fadc6a8c/hif/hostcmd.h",
  },
  {
    "id":"mwlwifi-fwcmd",
    "class":"exact-host-implementation",
    "url":"https://raw.githubusercontent.com/kaloz/mwlwifi/db97edf20fadea2617805006f5230665fadc6a8c/hif/fwcmd.c",
  },
  {
    "id":"nxp-hostcmdcommon",
    "class":"related-family-semantic-donor",
    "url":"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/dfb9d765615a748f064dfcfa7e289c43d846a15e/CMIF/include/hostcmdcommon.h",
  },
  {
    "id":"nxp-keymgmt-common",
    "class":"related-family-semantic-donor",
    "url":"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/dfb9d765615a748f064dfcfa7e289c43d846a15e/DRV/wlan-v10/core/incl/keyMgmtCommon.h",
  },
  {
    "id":"nxp-keymgmt",
    "class":"related-family-semantic-donor",
    "url":"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/dfb9d765615a748f064dfcfa7e289c43d846a15e/DRV/wlan-v10/core/encr/AP/keyMgmt.c",
  },
  {
    "id":"nxp-tkip",
    "class":"related-family-semantic-donor",
    "url":"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/dfb9d765615a748f064dfcfa7e289c43d846a15e/DRV/wlan-v10/core/encr/tkip.c",
  },
]
TOKENS=[
 "HOSTCMD_CMD_UPDATE_ENCRYPTION","ENCR_ACTION_TYPE_ENABLE_HW_ENCR","ENCR_ACTION_TYPE_SET_KEY",
 "ENCR_ACTION_TYPE_REMOVE_KEY","ENCR_ACTION_TYPE_SET_GROUP_KEY","KEY_TYPE_ID_WEP","KEY_TYPE_ID_TKIP",
 "KEY_TYPE_ID_AES","KEY_TYPE_ID_CCMP","KEY_FLAG","PAIRWISE","GROUP","TSC","MIC","TKIP","CCMP","WEP",
 "keymgmt_wlCipher2AesMode","HostCmd_FW_UPDATE_ENCRYPTION","KEY_PARAM_SET"
]
DEFINE_RE=re.compile(r"^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+([^/\n]+)",re.M)

def fetch(url:str)->bytes:
    req=urllib.request.Request(url,headers={"User-Agent":UA})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read()

def snippets(text:str, token:str, radius:int=500, cap:int=12):
    out=[]; start=0
    low=text.lower(); needle=token.lower()
    while len(out)<cap:
        i=low.find(needle,start)
        if i<0: break
        a=max(0,i-radius); b=min(len(text),i+len(token)+radius)
        out.append(text[a:b])
        start=i+len(token)
    return out

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--out",required=True); ns=ap.parse_args()
    out=Path(ns.out); out.parent.mkdir(parents=True,exist_ok=True)
    records=[]
    aggregate={}
    for src in SOURCES:
        raw=fetch(src["url"]); text=raw.decode("utf-8","replace")
        defs={k:v.strip() for k,v in DEFINE_RE.findall(text)}
        hits={}
        for tok in TOKENS:
            ss=snippets(text,tok)
            if ss: hits[tok]=ss
        selected_defs={k:v for k,v in defs.items() if any(t.lower() in k.lower() for t in
            ["ENCR","KEY_TYPE","KEY_FLAG","CIPHER","TKIP","CCMP","WEP"])}
        records.append({
            **src,"sha256":hashlib.sha256(raw).hexdigest(),"size":len(raw),
            "selected_defines":selected_defs,"token_hits":hits
        })
        for k,v in selected_defs.items():
            aggregate.setdefault(k,[]).append({"source":src["id"],"class":src["class"],"value":v})
    report={
      "schema":"wrt8964-crypto-source-oracle/v1",
      "sources":records,
      "cross_source_defines":aggregate,
      "promotion_rule":"exact-host-abi facts may describe the host contract directly; related-family donor semantics require matching 88W8964 binary data flow/constants before promotion.",
    }
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
      "sources":len(records),
      "define_names":len(aggregate),
      "exact_key_types":{k:v for k,v in aggregate.items() if k in ("KEY_TYPE_ID_WEP","KEY_TYPE_ID_TKIP","KEY_TYPE_ID_AES","KEY_TYPE_ID_CCMP")}
    },indent=2,sort_keys=True))
    return 0 if len(records)==len(SOURCES) else 3
if __name__=="__main__": raise SystemExit(main())
