#!/usr/bin/env python3
"""Prepare a provenance-preserving ELF view of 88W8964 firmware for Ghidra.

This script acquires only the public redistributed 88W8964 image, validates the
Marvell download-record framing, reconstructs contiguous load segments, emits
an ELF32 little-endian ARM analysis image into ephemeral work storage, and
writes derived metadata only to the evidence directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

FW_URL = "https://raw.githubusercontent.com/kaloz/mwlwifi/db97edf20fadea2617805006f5230665fadc6a8c/bin/firmware/88W8964.bin"
FW_SHA256 = "ca23f5bb730fde399359a716481651c120e09c299d4e6bbec6fe718c6e87e751"
MWLWIFI_HOSTCMD_URL = "https://raw.githubusercontent.com/kaloz/mwlwifi/db97edf20fadea2617805006f5230665fadc6a8c/hif/hostcmd.h"
UA = "SemperSupra-WRT3200ACM-ghidra-prep/1.0"
CMD_RE = __import__("re").compile(r"^\s*#define\s+(HOSTCMD_CMD_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\b", __import__("re").M)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def fetch(url: str) -> bytes:
    req=urllib.request.Request(url, headers={"User-Agent":UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

def parse_records(data: bytes) -> list[dict[str, Any]]:
    off=0
    records=[]
    while off+16 <= len(data):
        rtype, addr, size, checksum=struct.unpack_from("<IIII", data, off)
        rec={"index":len(records),"file_offset":off,"type":rtype,"load_address":addr,"load_size":size,"header_checksum_field":checksum}
        if rtype==4:
            rec["meaning"]="end"; records.append(rec); off+=16; break
        if rtype==6:
            rec["meaning"]="split-marker"; records.append(rec); off+=16; continue
        if rtype!=1:
            raise ValueError("unknown record type %d at 0x%x" % (rtype,off))
        if size < 4 or off+16+size > len(data):
            raise ValueError("invalid record size %d at 0x%x" % (size,off))
        payload_off=off+16
        payload_len=size-4
        payload=data[payload_off:payload_off+payload_len]
        trailer=data[payload_off+payload_len:off+16+size]
        rec.update({
            "meaning":"load","payload_file_offset":payload_off,"payload_size":payload_len,
            "payload_end_address":addr+payload_len,"payload_sha256":sha256_bytes(payload),
            "trailer_hex":trailer.hex()
        })
        records.append(rec)
        off += 16+size
    if off != len(data):
        raise ValueError("record stream did not consume artifact: %d of %d" % (off,len(data)))
    if not records or records[-1].get("type") != 4:
        raise ValueError("record stream did not terminate with type 4")
    return records

def reconstruct_segments(data: bytes, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    segs=[]
    cur=None
    for r in records:
        if r["type"] != 1:
            if cur is not None:
                segs.append(cur); cur=None
            continue
        payload=data[r["payload_file_offset"]:r["payload_file_offset"]+r["payload_size"]]
        addr=r["load_address"]
        if cur is None or addr != cur["end"]:
            if cur is not None:
                segs.append(cur)
            cur={"start":addr,"end":addr+len(payload),"data":bytearray(payload),"record_indices":[r["index"]]}
        else:
            cur["data"].extend(payload); cur["end"]=addr+len(payload); cur["record_indices"].append(r["index"])
    if cur is not None:
        segs.append(cur)
    return segs

def write_elf32_arm(path: Path, segments: list[dict[str, Any]]) -> None:
    # Analysis container only: ELF32 LE, EM_ARM, entry at 0, PT_LOAD segments.
    ident=b"\x7fELF"+bytes([1,1,1,0])+bytes(8)
    ehsize=52; phentsize=32; phnum=len(segments); phoff=ehsize
    header=ident+struct.pack("<HHIIIIIHHHHHH",2,40,1,0,phoff,0,0,ehsize,phentsize,phnum,0,0,0)
    data_off=ehsize+phentsize*phnum
    phdrs=[]
    cursor=data_off
    for seg in segments:
        blob=bytes(seg["data"])
        phdrs.append(struct.pack("<IIIIIIII",1,cursor,seg["start"],seg["start"],len(blob),len(blob),7,1))
        cursor += len(blob)
    with path.open("wb") as f:
        f.write(header)
        for p in phdrs: f.write(p)
        for seg in segments: f.write(bytes(seg["data"]))

def map_container_offset(records: list[dict[str, Any]], off: int) -> int|None:
    for r in records:
        if r["type"] != 1: continue
        a=r["payload_file_offset"]; b=a+r["payload_size"]
        if a <= off < b:
            return r["load_address"] + (off-a)
    return None

def command_anchor_map(data: bytes, records: list[dict[str, Any]], hostcmd_text: str) -> dict[str, Any]:
    cmds=[]
    for name,val_s in CMD_RE.findall(hostcmd_text):
        cmds.append((name,int(val_s,16)))
    hits=[]
    window=defaultdict(set)
    for name,val in cmds:
        needle=struct.pack("<H",val)
        start=0; count=0
        while count<512:
            idx=data.find(needle,start)
            if idx<0: break
            load=map_container_offset(records,idx)
            if load is not None:
                hits.append({"command":name,"value":val,"hex":"0x%04x"%val,"container_offset":idx,"load_address":load})
                window[(load//256)*256].add((name,val))
            start=idx+1; count+=1
    ranked=[]
    for base,vals in window.items():
        if len(vals)>=4:
            ranked.append({"load_address":base,"distinct_commands":len(vals),
                           "commands":[{"name":n,"hex":"0x%04x"%v} for n,v in sorted(vals)]})
    ranked.sort(key=lambda x:(-x["distinct_commands"],x["load_address"]))
    return {"schema":"wrt8964-hostcmd-loaded-anchors/v1","hit_count":len(hits),"hits":hits,
            "candidate_windows_256b":ranked[:100],
            "warning":"Literal command-ID density is an anchor generator, not proof of dispatch semantics."}

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--work",required=True)
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    work=Path(ns.work); out=Path(ns.out)
    work.mkdir(parents=True,exist_ok=True); out.mkdir(parents=True,exist_ok=True)
    fw=fetch(FW_URL)
    got=sha256_bytes(fw)
    if got != FW_SHA256:
        raise SystemExit("88W8964 digest mismatch: %s" % got)
    records=parse_records(fw)
    segs=reconstruct_segments(fw,records)
    recon=work/"reconstructed"; recon.mkdir(exist_ok=True)
    segment_meta=[]
    for i,seg in enumerate(segs):
        blob=bytes(seg["data"])
        p=recon/("segment-%02d-%08x.bin"%(i,seg["start"]))
        p.write_bytes(blob)
        segment_meta.append({
            "index":i,"start":seg["start"],"end":seg["end"],"size":len(blob),
            "sha256":sha256_bytes(blob),"record_count":len(seg["record_indices"]),
            "head_64_hex":blob[:64].hex(),"tail_64_hex":blob[-64:].hex()
        })
    elf=recon/"88W8964.elf"
    write_elf32_arm(elf,segs)
    hostcmd=fetch(MWLWIFI_HOSTCMD_URL).decode("utf-8","replace")
    anchors=command_anchor_map(fw,records,hostcmd)
    (out/"88W8964.loaded-hostcmd-anchors.json").write_text(json.dumps(anchors,indent=2,sort_keys=True)+"\n")
    prep={
        "schema":"wrt8964-ghidra-prep/v1",
        "source":{"url":FW_URL,"sha256":got,"size":len(fw)},
        "processor_evidence":{"family":"Arm Cortex-A9","isa_family":"ARMv7-A","source":"NXP 88W8964 fact sheet"},
        "record_stream":{"record_count":len(records),"termination":records[-1]["meaning"]},
        "segments":segment_meta,
        "analysis_elf":{"path":str(elf),"sha256":__import__("hashlib").sha256(elf.read_bytes()).hexdigest(),
                        "format":"ELF32 little-endian EM_ARM","entry":"0x00000000",
                        "note":"Synthetic analysis container preserving validated load addresses; not a vendor-distributed executable."},
        "anchor_windows_top10":anchors["candidate_windows_256b"][:10]
    }
    (out/"88W8964.ghidra-prep.json").write_text(json.dumps(prep,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"segments":[[hex(x["start"]),hex(x["end"]),x["size"]] for x in segment_meta],
                      "anchor_windows":len(anchors["candidate_windows_256b"]),"elf":str(elf)},indent=2))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
