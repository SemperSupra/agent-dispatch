#!/usr/bin/env python3
"""Probe the 0x706c0+0 MAC-comparison mask and W8964 virtual-MAC source contract."""
from __future__ import annotations
import argparse, importlib.util, json, re, urllib.request
from pathlib import Path

REF="db97edf20fadea2617805006f5230665fadc6a8c"
CORE=f"https://raw.githubusercontent.com/kaloz/mwlwifi/{REF}/core.c"
P=Path(__file__).with_name("wrt3200acm_dispatch_probe.py")
spec=importlib.util.spec_from_file_location("dp",P)
dp=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(dp)

def fetch(url:str)->str:
    req=urllib.request.Request(url,headers={"User-Agent":"SemperSupra-WRT-anchor0-mask/1.0"})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")

def context(ins:list[dict],i:int,n:int=16)->list[str]:
    return [x["text"] for x in ins[max(0,i-n):min(len(ins),i+n+1)]]

def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True)
    ns=ap.parse_args(); elf=Path(ns.elf); out=Path(ns.out); out.mkdir(parents=True,exist_ok=True)
    core=fetch(CORE)
    src={
      "w8964_multiple_addresses": "if (priv->chip_type == MWL8964)" in core and "SYSADPT_NUM_OF_AP + SYSADPT_NUM_OF_CLIENT" in core,
      "last_nibble_from_permanent_mac": "last_nibble = mac_addr->addr[5] & 0x0F;" in core,
      "virtual_ap_changes_only_last_low_nibble": "(mac_addr->addr[5] & 0xF0) | last_nibble" in core,
      "virtual_ap_sets_local_admin_bit": "mac_addr->addr[0] |= 0x2;" in core,
    }
    raw=dp.run_objdump(elf,0x2a29c,0x2a620)
    ins=dp.parse_instructions(raw)
    hits=[]
    for i,x in enumerate(ins):
        t=x["text"].lower()
        if any(k in t for k in ("0xf0ff","61695","r7","[sp, #24]")) or (
            x["mnemonic"].startswith("strh") and re.search(r"\[[^\]]+\](?:\s|$)",x["operands"])
        ):
            hits.append({"pc":x["address"],"text":x["text"],"context":context(ins,i)})
    report={
      "schema":"wrt8964-anchor0-macmask-probe/v1",
      "source_ref":REF,
      "source_url":CORE,
      "source_checks":src,
      "predicted_mask":{
        "value":"0xf0ff",
        "derivation":"Little-endian halfword covering MAC bytes 4..5 with the low nibble of byte 5 ignored: byte4 mask 0xff, byte5 mask 0xf0 -> 0xf0ff.",
        "first_octet_rule":"The same source sets locally-administered bit 0x02 in byte0; firmware key/enable comparisons independently clear bit 0x02 from the first MAC halfword before equality tests."
      },
      "function_range":"0x2a29c..0x2a620",
      "contains_f0ff":any("0xf0ff" in x["text"].lower() for x in ins),
      "interesting":hits,
      "instructions":[x["text"] for x in ins],
      "guardrail":"This probe does not promote +0 as the mask until an exact data-flow from the 0xf0ff value to the anchor field, or an equivalent independently validated writer, is recovered."
    }
    (out/"anchor0-macmask-probe.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"source_checks":src,"contains_f0ff":report["contains_f0ff"],"interesting":hits},indent=2,sort_keys=True))
    return 0 if all(src.values()) and report["contains_f0ff"] else 3

if __name__=="__main__":
    raise SystemExit(main())
