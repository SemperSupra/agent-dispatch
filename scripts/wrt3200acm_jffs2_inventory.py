#!/usr/bin/env python3
"""Checksum-aware JFFS2 directory inventory for the stock WRT3200ACM image.

Only metadata is emitted. The OEM image stays in ephemeral runner storage.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import zlib
from pathlib import Path
from typing import Any

MAGIC=0x1985
DIRENT=0xE001
ROOT_INO=1

def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xffffffff

def parse_nodes(data: bytes, start: int=0) -> dict[str, Any]:
    off=start
    nodes=0
    valid_headers=0
    invalid_headers=0
    dirents=[]
    nodetypes={}
    while off+12 <= len(data):
        idx=data.find(b"\x85\x19",off)
        if idx < 0:
            break
        off=idx
        if off+12 > len(data):
            break
        magic,nodetype,totlen,hdr_crc=struct.unpack_from("<HHII",data,off)
        if magic != MAGIC or totlen < 12 or off+totlen > len(data):
            off += 2
            continue
        nodes += 1
        nodetypes[f"0x{nodetype:04x}"]=nodetypes.get(f"0x{nodetype:04x}",0)+1
        hdr_ok=(crc32(data[off:off+8])==hdr_crc)
        if hdr_ok: valid_headers += 1
        else: invalid_headers += 1
        if nodetype == DIRENT and totlen >= 40:
            pino,version,ino,mctime=struct.unpack_from("<IIII",data,off+12)
            nsize=data[off+28]
            dtype=data[off+29]
            node_crc,name_crc=struct.unpack_from("<II",data,off+32)
            if 40+nsize <= totlen:
                name_b=data[off+40:off+40+nsize]
                name_ok=(crc32(name_b)==name_crc)
                try: name=name_b.decode("utf-8")
                except UnicodeDecodeError: name=name_b.decode("utf-8","replace")
                dirents.append({
                    "offset":off,"pino":pino,"version":version,"ino":ino,"mctime":mctime,
                    "type":dtype,"name":name,"header_crc_ok":hdr_ok,"name_crc_ok":name_ok,
                    "node_crc_field":node_crc
                })
        off=(off+totlen+3)&~3
    return {
        "node_count":nodes,
        "valid_header_crc_count":valid_headers,
        "invalid_header_crc_count":invalid_headers,
        "nodetypes":nodetypes,
        "dirents":dirents,
    }

def active_dirents(dirents: list[dict[str,Any]]) -> list[dict[str,Any]]:
    latest={}
    for d in dirents:
        if not d["header_crc_ok"] or not d["name_crc_ok"]:
            continue
        key=(d["pino"],d["name"])
        if key not in latest or d["version"] > latest[key]["version"]:
            latest[key]=d
    return [d for d in latest.values() if d["ino"] != 0]

def build_paths(entries: list[dict[str,Any]]) -> list[dict[str,Any]]:
    paths={ROOT_INO:"/"}
    unresolved=list(entries)
    out=[]
    for _ in range(len(entries)+2):
        changed=False
        remain=[]
        for d in unresolved:
            parent=paths.get(d["pino"])
            if parent is None:
                remain.append(d); continue
            path=(parent.rstrip("/")+"/"+d["name"]) if parent != "/" else "/"+d["name"]
            row=dict(d); row["path"]=path; out.append(row)
            if d["ino"] not in paths or d["type"]==4:
                paths[d["ino"]]=path
            changed=True
        unresolved=remain
        if not changed:
            break
    return sorted(out,key=lambda x:x["path"])

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--offset",type=lambda x:int(x,0),default=0x600000)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    data=Path(ns.image).read_bytes()
    parsed=parse_nodes(data,ns.offset)
    active=active_dirents(parsed["dirents"])
    paths=build_paths(active)
    interesting_re=re.compile(r"(?:firmware|mwl|wifi|wireless|wlan|marvell|regulatory|calibr|radio)",re.I)
    interesting=[x for x in paths if interesting_re.search(x["path"])]
    report={
        "schema":"wrt3200acm-stock-jffs2-inventory/v1",
        "image_size":len(data),
        "scan_offset":ns.offset,
        "node_count":parsed["node_count"],
        "valid_header_crc_count":parsed["valid_header_crc_count"],
        "invalid_header_crc_count":parsed["invalid_header_crc_count"],
        "nodetypes":parsed["nodetypes"],
        "dirent_observations":len(parsed["dirents"]),
        "active_dirents":len(active),
        "resolved_paths":len(paths),
        "unresolved_active_dirents":len(active)-len(paths),
        "interesting_paths":interesting[:5000],
        "paths":[{"path":x["path"],"ino":x["ino"],"pino":x["pino"],"type":x["type"],"version":x["version"]} for x in paths[:20000]],
        "note":"Derived directory metadata only; no OEM file payloads are emitted."
    }
    out=Path(ns.out); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:report[k] for k in [
        "node_count","valid_header_crc_count","invalid_header_crc_count",
        "dirent_observations","active_dirents","resolved_paths","unresolved_active_dirents"
    ]},indent=2))
    print("interesting_paths",len(interesting))
    for x in interesting[:50]:
        print(x["path"])
    if report["valid_header_crc_count"] < 10 or report["resolved_paths"] < 10:
        return 3
    return 0

if __name__=="__main__":
    raise SystemExit(main())
