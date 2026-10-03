#!/usr/bin/env python3
"""Reconstruct Marvell firmware download records into a transient ELF32/ARM image.

The output ELF contains vendor firmware bytes and is therefore a work product
for ephemeral analysis only. Public artifacts must contain only the JSON map
and derived Ghidra reports, never the ELF itself.
"""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path

PT_LOAD=1
PF_X=1
PF_W=2
PF_R=4
EM_ARM=40

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse_records(data: bytes):
    off=0
    records=[]
    while off+16<=len(data):
        typ,addr,size,checksum=struct.unpack_from("<IIII",data,off)
        if typ==4:
            records.append({"type":4,"file_offset":off})
            off+=16
            break
        if typ==6:
            records.append({"type":6,"file_offset":off})
            off+=16
            continue
        if typ!=1 or size<4 or off+16+size>len(data):
            raise ValueError(f"invalid Marvell record at 0x{off:x}: type={typ} size={size}")
        payload_off=off+16
        payload_len=size-4
        payload=data[payload_off:payload_off+payload_len]
        records.append({
            "type":1,"file_offset":off,"load_address":addr,
            "payload_file_offset":payload_off,"payload_size":payload_len,
            "payload":payload,"payload_sha256":sha256_bytes(payload),
            "trailer":data[payload_off+payload_len:off+16+size].hex(),
            "header_checksum_field":checksum,
        })
        off+=16+size
    if off!=len(data):
        raise ValueError(f"record stream did not consume input: 0x{off:x}/0x{len(data):x}")
    return records

def merge_ranges(records):
    loads=[r for r in records if r["type"]==1]
    if not loads:
        raise ValueError("no load records")
    ranges=[]
    cur={"address":loads[0]["load_address"],"data":bytearray(loads[0]["payload"]),"record_indices":[0]}
    last_end=cur["address"]+len(cur["data"])
    for idx,r in enumerate(loads[1:],start=1):
        if r["load_address"]==last_end:
            cur["data"].extend(r["payload"])
            cur["record_indices"].append(idx)
        else:
            ranges.append(cur)
            cur={"address":r["load_address"],"data":bytearray(r["payload"]),"record_indices":[idx]}
        last_end=cur["address"]+len(cur["data"])
    ranges.append(cur)
    return ranges

def write_elf(path: Path, ranges):
    ehsize=52
    phentsize=32
    phnum=len(ranges)
    phoff=ehsize
    data_off=(ehsize+phentsize*phnum+0xfff)&~0xfff
    offsets=[]
    cursor=data_off
    for r in ranges:
        offsets.append(cursor)
        cursor=(cursor+len(r["data"])+0xfff)&~0xfff

    ident=bytes([0x7f,ord("E"),ord("L"),ord("F"),1,1,1,0]+[0]*8)
    hdr=struct.pack("<16sHHIIIIIHHHHHH",ident,2,EM_ARM,1,0,phoff,0,0,ehsize,phentsize,phnum,0,0,0)
    with path.open("wb") as f:
        f.write(hdr)
        for i,r in enumerate(ranges):
            # The 0-based range contains exception vectors and executable code.
            # High ranges are conservatively RW; permissions do not assert semantics.
            flags=PF_R|PF_X if r["address"]==0 else PF_R|PF_W
            f.write(struct.pack("<IIIIIIII",PT_LOAD,offsets[i],r["address"],r["address"],len(r["data"]),len(r["data"]),flags,0x1000))
        f.seek(data_off)
        for i,r in enumerate(ranges):
            f.seek(offsets[i])
            f.write(r["data"])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("elf")
    ap.add_argument("map_json")
    ns=ap.parse_args()
    src=Path(ns.input)
    data=src.read_bytes()
    records=parse_records(data)
    ranges=merge_ranges(records)
    write_elf(Path(ns.elf),ranges)
    summary={
        "schema":"marvell-fw-to-elf/v1",
        "source_sha256":sha256_bytes(data),
        "source_size":len(data),
        "record_count":len(records),
        "ranges":[{
            "address":r["address"],
            "end_address":r["address"]+len(r["data"]),
            "size":len(r["data"]),
            "sha256":sha256_bytes(bytes(r["data"])),
            "record_count":len(r["record_indices"])
        } for r in ranges],
        "elf_sha256":hashlib.sha256(Path(ns.elf).read_bytes()).hexdigest(),
        "elf_note":"Transient analysis derivative containing firmware bytes; do not publish or upload."
    }
    Path(ns.map_json).write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print(json.dumps(summary,indent=2,sort_keys=True))

if __name__=="__main__":
    main()
