#!/usr/bin/env python3
"""Correlate the recovered 0x706c0+0x208 firmware arena with open Marvell/NXP TX-queue semantics."""
from __future__ import annotations
import argparse, hashlib, json, re, urllib.request
from pathlib import Path

REF="dfb9d765615a748f064dfcfa7e289c43d846a15e"
BASE=f"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/{REF}/"
SOURCES={
  "buildModes":BASE+"DRV/wlan-v10/core/incl/buildModes.h",
  "w8964_xmit":BASE+"DRV/wlan-v10/driver/W8964/ap8xLnxXmit.c",
  "atf":BASE+"DRV/wlan-v10/driver/ap8xLnxAtf.c",
  "smac_hal":BASE+"SHAL/shal1/include/smac_hal_inf.h",
}
UA="SemperSupra-WRT3200ACM-TXQ-correlation/1.0"

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":UA})
    with urllib.request.urlopen(req,timeout=45) as r:return r.read()

def need(text,pattern,label):
    m=re.search(pattern,text,re.M|re.S)
    if not m: raise RuntimeError(f"missing source anchor: {label}")
    return m.group(0)

def main()->int:
    ap=argparse.ArgumentParser();ap.add_argument("--out",required=True);ns=ap.parse_args()
    raw={k:fetch(v) for k,v in SOURCES.items()}
    t={k:v.decode("utf-8","replace") for k,v in raw.items()}

    anchors={
      "legacy_max_tid_8":need(t["buildModes"],r"#else\s*#define\s+OEMCHANNEL\s+6.*?#define\s+MAX_STNS\s+300.*?#define\s+MAX_TID\s+8", "legacy MAX_TID=8"),
      "smac_qid_per_sta_8":need(t["smac_hal"],r"#define\s+SMAC_QID_PER_STA\s+8\b","SMAC_QID_PER_STA=8"),
      "num_txqueue_3072":need(t["atf"],r"#define\s+NUM_TXQUEUE\s+3072\b[^\n]*","NUM_TXQUEUE=3072"),
      "w8964_probe_queue_formula":need(t["w8964_xmit"],r"#define\s+PROBE_RESPONSE_TXQNUM\s+\(\(MAX_STNS\s*\+\s*NUMOFAPS\s*\+\s*NUMOFCLIENTS\)\s*\*\s*MAX_TID\)","W8964 queue formula"),
    }

    firmware={
      "arena_bytes":0x01878000,
      "record_count":0xc00,
      "record_stride":0x20a0,
      "per_macid_stride":0x10500,
      "records_per_macid":0x10500//0x20a0,
    }
    acceptance={
      "arena_arithmetic_exact":firmware["arena_bytes"]==firmware["record_count"]*firmware["record_stride"],
      "eight_records_per_macid":firmware["records_per_macid"]==8,
      "source_qid_per_sta_matches":firmware["records_per_macid"]==8,
      "source_txqueue_capacity_matches_record_count":firmware["record_count"]==3072,
    }
    report={
      "schema":"wrt8964-txqueue-source-correlation/v1",
      "source_ref":REF,
      "source_digests":{k:hashlib.sha256(v).hexdigest() for k,v in raw.items()},
      "source_anchors":anchors,
      "firmware_observations":firmware,
      "acceptance":acceptance,
      "all_acceptance_pass":all(acceptance.values()),
      "interpretation":{
        "supported":"The +0x208 runtime allocation is strongly identified as a TX-queue state arena: firmware has exactly 3072 records and groups them eight at a time, while Marvell/NXP source independently defines NUM_TXQUEUE=3072 and eight queue/TID IDs per station.",
        "not_supported":"Do not infer that 3072/8=384 means 384 ordinary associated stations. Queue-ID namespaces can include BSS/client/reserved IDs; the exact ID partition remains unresolved."
      }
    }
    Path(ns.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"acceptance":acceptance,"firmware":firmware},indent=2,sort_keys=True))
    return 0 if report["all_acceptance_pass"] else 3

if __name__=="__main__": raise SystemExit(main())
