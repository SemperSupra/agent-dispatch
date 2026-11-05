#!/usr/bin/env python3
"""Identify the stock W8964 firmware against public mwlwifi history without publishing blobs."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import urllib.request
from pathlib import Path
from typing import Any

HISTORY = [
    ("b0aeee507f1534ae40fab9d2420a6319e1f33de5","2020-02-06","9.3.2.12"),
    ("11896425a9fe6d576b52864d8d0945656db3d551","2018-03-30","9.3.2.6"),
    ("2e5d650821fa91a98b451bcf1d2180365ec4f220","2018-02-26","9.3.2.5"),
    ("5955f5ea40a51f9ed4c6a85b4b94cfece1b4f716","2018-01-16","9.3.2.4"),
    ("b04d5599f7cc3e7b287c6304f6da8724ccb37aaf","2017-12-12","9.3.2.2"),
    ("05b3e03c3183fabc408e7f85d89bc13985397552","2017-12-01","9.3.2.1"),
    ("e119077b68d64e368cb9cc46bd364308db4289dc","2017-10-11","9.3.0.8"),
    ("2d4b9bcd6c82043284fc83a3b4c92d93db39a9c1","2017-05-26","9.3.0.7"),
    ("14ab9c3f00b537d60334d6752623ee5d8975783f","2017-05-16","9.3.0.6"),
    ("5fac04c8f9b1631d9c402c79b65342be251faaaa","2017-01-25","9.1.2.5"),
    ("0aaa391b2042080410f4299889c0c6adecd6fe65","2016-10-13","7.8.0.4"),
    ("d021212433b8a6ee416118620b17c41483f4afa9","2016-10-12","7.8.0.3"),
]
RAW="https://raw.githubusercontent.com/kaloz/mwlwifi/{sha}/bin/firmware/88W8964.bin"
UA="SemperSupra-WRT3200ACM-lineage/1.0"
EXTERNAL_CANDIDATES = [
    {
        "id":"wrt32x-gpl-shipped",
        "provenance":"wongsyrone public recovery of WRT32X GPL tarball",
        "url":"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/dfb9d765615a748f064dfcfa7e289c43d846a15e/extracted-from-WRT32X-gpl-tarball/wlan-v9_8964/files/shipped/W8964.bin",
    },
    {
        "id":"nxp-wlan-v10-w8964",
        "provenance":"wongsyrone NXP wlan-v10 recovered package",
        "url":"https://raw.githubusercontent.com/wongsyrone/nxp-W9064-PR25-25.2.2.0-P1077-D2082-WFO/dfb9d765615a748f064dfcfa7e289c43d846a15e/DRV/wlan-v10/W8964.bin",
    },
]

def sha256_bytes(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def fetch(url:str)->bytes:
    req=urllib.request.Request(url,headers={"User-Agent":UA})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read()

def parse_records(data:bytes)->list[dict[str,Any]]:
    out=[]; off=0
    while off+16<=len(data):
        typ,addr,size,checksum=struct.unpack_from("<IIII",data,off)
        rec={"index":len(out),"file_offset":off,"type":typ,"load_address":addr,"load_size":size,"checksum_field":checksum}
        if typ==4:
            out.append(rec); off+=16; break
        if typ==6:
            out.append(rec); off+=16; continue
        if typ!=1 or size<4 or off+16+size>len(data):
            rec["invalid"]=True; out.append(rec); break
        payload=data[off+16:off+16+size-4]
        rec["payload_sha256"]=sha256_bytes(payload)
        rec["payload_size"]=len(payload)
        out.append(rec)
        off+=16+size
    return out

def compare(a:bytes,b:bytes)->dict[str,Any]:
    n=min(len(a),len(b))
    diffs=[i for i in range(n) if a[i]!=b[i]]
    changed=len(diffs)+abs(len(a)-len(b))
    first=diffs[:64]
    ra=parse_records(a); rb=parse_records(b)
    common=min(len(ra),len(rb))
    same_payload=sum(
        1 for i in range(common)
        if ra[i].get("payload_sha256") is not None and ra[i].get("payload_sha256")==rb[i].get("payload_sha256")
    )
    changed_records=[
        i for i in range(common)
        if ra[i].get("payload_sha256") is not None and rb[i].get("payload_sha256") is not None
        and ra[i].get("payload_sha256")!=rb[i].get("payload_sha256")
    ]
    return {
        "size_a":len(a),"size_b":len(b),
        "changed_byte_count":changed,
        "changed_byte_fraction":round(changed/max(len(a),len(b),1),8),
        "first_changed_offsets":first,
        "record_count_a":len(ra),"record_count_b":len(rb),
        "same_payload_record_count":same_payload,
        "changed_payload_record_count":len(changed_records),
        "first_changed_payload_record_indices":changed_records[:64],
    }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("stock_w8964")
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    stock=Path(ns.stock_w8964).read_bytes()
    stock_sha=sha256_bytes(stock)
    rows=[]
    for sha,date,version in HISTORY:
        url=RAW.format(sha=sha)
        try:
            data=fetch(url)
            row={
                "commit":sha,"date":date,"version":version,"url":url,
                "size":len(data),"sha256":sha256_bytes(data),
                "exact_match":data==stock,
            }
            row["comparison"]=compare(stock,data)
        except Exception as exc:
            row={"commit":sha,"date":date,"version":version,"url":url,"error":repr(exc),"exact_match":False}
        rows.append(row)
    external=[]
    for cand in EXTERNAL_CANDIDATES:
        try:
            data=fetch(cand["url"])
            row={**cand,"size":len(data),"sha256":sha256_bytes(data),"exact_match":data==stock}
            row["comparison"]=compare(stock,data)
        except Exception as exc:
            row={**cand,"error":repr(exc),"exact_match":False}
        external.append(row)
    exact=[r for r in rows if r.get("exact_match")]
    external_exact=[r for r in external if r.get("exact_match")]
    comparable=[r for r in rows+external if "comparison" in r]
    nearest=min(comparable,key=lambda r:r["comparison"]["changed_byte_count"]) if comparable else None
    report={
        "schema":"wrt3200acm-stock-w8964-lineage/v1",
        "stock":{"sha256":stock_sha,"size":len(stock)},
        "history_source":"GitHub commit history for kaloz/mwlwifi bin/firmware/88W8964.bin",
        "candidates":rows,
        "external_candidates":external,
        "exact_matches":[{"kind":"mwlwifi-history","commit":r["commit"],"date":r["date"],"version":r["version"],"sha256":r["sha256"]} for r in exact]
            + [{"kind":"external-public","id":r["id"],"provenance":r["provenance"],"sha256":r["sha256"]} for r in external_exact],
        "nearest_public_revision":None if nearest is None else {
            **({"commit":nearest["commit"],"date":nearest["date"],"version":nearest["version"]} if "commit" in nearest else
               {"id":nearest["id"],"provenance":nearest["provenance"]}),
            "sha256":nearest["sha256"],"comparison":nearest["comparison"]
        },
        "note":"Historical firmware bytes were downloaded only into ephemeral runner memory; evidence contains hashes and delta metrics only."
    }
    Path(ns.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
        "stock_sha256":stock_sha,
        "exact_matches":report["exact_matches"],
        "nearest_public_revision":report["nearest_public_revision"]
    },indent=2,sort_keys=True))
    return 0 if comparable else 3

if __name__=="__main__":
    raise SystemExit(main())
