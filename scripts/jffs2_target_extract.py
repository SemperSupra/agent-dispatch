#!/usr/bin/env python3
"""CRC-validated JFFS2 targeted-file reconstructor.

This exists because mtd-utils jffs2reader -f reconstructs only one raw inode
node and can therefore zero-fill fragmented files. We replay all valid raw
inode versions for a selected pathname and keep reconstructed bytes in
ephemeral storage only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path
from typing import Any

MAGIC=0x1985
NODETYPE_DIRENT=0xE001
NODETYPE_INODE=0xE002
COMPR_NONE=0x00
COMPR_ZERO=0x01
COMPR_RTIME=0x02
COMPR_COPY=0x04
COMPR_ZLIB=0x06
RAW_INODE_SIZE=68

def crc32_raw(data: bytes) -> int:
    return (zlib.crc32(data,0xffffffff)^0xffffffff)&0xffffffff

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def iter_nodes(data: bytes):
    off=0
    n=len(data)
    while off+12<=n:
        if data[off:off+2]!=b"\x85\x19":
            off+=4
            continue
        magic,nodetype,totlen,hdr_crc=struct.unpack_from("<HHII",data,off)
        if magic!=MAGIC or totlen<12 or off+totlen>n:
            off+=4
            continue
        yield off,nodetype,totlen,hdr_crc,data[off:off+totlen]
        off=(off+totlen+3)&~3

def parse_dirents(data: bytes) -> list[dict[str,Any]]:
    rows=[]
    for off,nodetype,totlen,hdr_crc,node in iter_nodes(data):
        if nodetype!=NODETYPE_DIRENT or totlen<40:
            continue
        hdr_ok=crc32_raw(node[:8])==hdr_crc
        pino,version,ino,mctime=struct.unpack_from("<IIII",node,12)
        nsize=node[28]; dtype=node[29]
        node_crc,name_crc=struct.unpack_from("<II",node,32)
        if 40+nsize>len(node):
            continue
        name_b=node[40:40+nsize]
        name_ok=crc32_raw(name_b)==name_crc
        node_ok=crc32_raw(node[:32])==node_crc
        rows.append({
            "flash_offset":off,"pino":pino,"version":version,"ino":ino,
            "mctime":mctime,"nsize":nsize,"type":dtype,
            "name":name_b.decode("utf-8","replace"),
            "hdr_crc_ok":hdr_ok,"node_crc_ok":node_ok,"name_crc_ok":name_ok,
        })
    return rows

def latest_dirents(rows: list[dict[str,Any]]) -> list[dict[str,Any]]:
    latest={}
    for r in rows:
        if not (r["hdr_crc_ok"] and r["node_crc_ok"] and r["name_crc_ok"]):
            continue
        key=(r["pino"],r["name"])
        if key not in latest or r["version"]>latest[key]["version"]:
            latest[key]=r
    return [r for r in latest.values() if r["ino"]!=0]

def resolve_paths(rows: list[dict[str,Any]]) -> dict[str,int]:
    paths={"/":1}
    inode_paths={1:"/"}
    unresolved=list(rows)
    for _ in range(len(rows)+2):
        changed=False; remain=[]
        for r in unresolved:
            parent=inode_paths.get(r["pino"])
            if parent is None:
                remain.append(r); continue
            p=(parent.rstrip("/")+"/"+r["name"]) if parent!="/" else "/"+r["name"]
            paths[p]=r["ino"]
            if r["type"]==4:
                inode_paths[r["ino"]]=p
            changed=True
        unresolved=remain
        if not changed:
            break
    return paths

def parse_inode_nodes(data: bytes, ino: int) -> list[dict[str,Any]]:
    rows=[]
    for flash_off,nodetype,totlen,hdr_crc,node in iter_nodes(data):
        if nodetype!=NODETYPE_INODE or totlen<RAW_INODE_SIZE:
            continue
        node_ino=struct.unpack_from("<I",node,12)[0]
        if node_ino!=ino:
            continue
        version=struct.unpack_from("<I",node,16)[0]
        mode=struct.unpack_from("<I",node,20)[0]
        uid,gid=struct.unpack_from("<HH",node,24)
        isize=struct.unpack_from("<I",node,28)[0]
        atime,mtime,ctime=struct.unpack_from("<III",node,32)
        file_off,csize,dsize=struct.unpack_from("<III",node,44)
        compr=node[56]; usercompr=node[57]; flags=struct.unpack_from("<H",node,58)[0]
        data_crc,node_crc=struct.unpack_from("<II",node,60)
        payload=node[RAW_INODE_SIZE:RAW_INODE_SIZE+csize]
        rows.append({
            "flash_offset":flash_off,"totlen":totlen,"ino":ino,"version":version,
            "mode":mode,"uid":uid,"gid":gid,"isize":isize,
            "atime":atime,"mtime":mtime,"ctime":ctime,
            "file_offset":file_off,"csize":csize,"dsize":dsize,
            "compr":compr,"usercompr":usercompr,"flags":flags,
            "hdr_crc_ok":crc32_raw(node[:8])==hdr_crc,
            "node_crc_ok":crc32_raw(node[:60])==node_crc,
            "data_crc_ok":crc32_raw(payload)==data_crc,
            "payload":payload,
        })
    return rows

def rtime_decompress(src: bytes, destlen: int) -> bytes:
    positions=[0]*256
    out=bytearray()
    pos=0
    while len(out)<destlen:
        if pos+2>len(src):
            raise ValueError("truncated rtime stream")
        value=src[pos]; repeat=src[pos+1]; pos+=2
        out.append(value)
        backoffs=positions[value]
        positions[value]=len(out)
        for _ in range(repeat):
            if len(out)>=destlen:
                break
            if backoffs>=len(out):
                raise ValueError("invalid rtime back-reference")
            out.append(out[backoffs]); backoffs+=1
    if len(out)!=destlen:
        raise ValueError("rtime length mismatch")
    return bytes(out)

def decompress_node(row: dict[str,Any]) -> bytes:
    c=row["compr"]; src=row["payload"]; dsize=row["dsize"]
    if dsize==0:
        return b""
    if c in (COMPR_NONE,COMPR_COPY):
        out=src
    elif c==COMPR_ZERO:
        out=b"\x00"*dsize
    elif c==COMPR_ZLIB:
        out=zlib.decompress(src)
    elif c==COMPR_RTIME:
        out=rtime_decompress(src,dsize)
    else:
        raise NotImplementedError(f"unsupported JFFS2 compression 0x{c:02x}")
    if len(out)!=dsize:
        raise ValueError(f"decompressed size mismatch {len(out)} != {dsize}")
    return out

def reconstruct_inode(rows: list[dict[str,Any]]) -> tuple[bytes,dict[str,Any]]:
    good=[r for r in rows if r["hdr_crc_ok"] and r["node_crc_ok"] and r["data_crc_ok"]]
    if not good:
        raise ValueError("no CRC-valid inode nodes")
    good.sort(key=lambda r:(r["version"],r["flash_offset"]))
    buf=bytearray()
    applied=[]
    for r in good:
        isize=r["isize"]
        if len(buf)>isize:
            del buf[isize:]
        elif len(buf)<isize:
            buf.extend(b"\x00"*(isize-len(buf)))
        payload=decompress_node(r)
        if payload:
            end=r["file_offset"]+len(payload)
            if end>len(buf):
                buf.extend(b"\x00"*(end-len(buf)))
            buf[r["file_offset"]:end]=payload
            if len(buf)>isize:
                del buf[isize:]
        applied.append({
            k:r[k] for k in ("flash_offset","version","isize","file_offset","csize","dsize","compr")
        })
    meta={
        "raw_inode_node_count":len(rows),
        "crc_valid_inode_node_count":len(good),
        "crc_invalid_inode_node_count":len(rows)-len(good),
        "compression_types":sorted(set(r["compr"] for r in good)),
        "final_size":len(buf),
        "final_sha256":sha256_bytes(bytes(buf)),
        "applied_nodes":applied,
    }
    return bytes(buf),meta

def extract_path(fs: bytes,path: str) -> tuple[bytes,dict[str,Any]]:
    d=parse_dirents(fs)
    active=latest_dirents(d)
    paths=resolve_paths(active)
    if path not in paths:
        raise FileNotFoundError(path)
    ino=paths[path]
    rows=parse_inode_nodes(fs,ino)
    blob,meta=reconstruct_inode(rows)
    meta.update({
        "path":path,"inode":ino,
        "dirent_total":len(d),"active_dirents":len(active),"resolved_path_count":len(paths),
    })
    return blob,meta

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("jffs2_image")
    ap.add_argument("--path",required=True)
    ap.add_argument("--output",required=True,help="ephemeral reconstructed file")
    ap.add_argument("--metadata",required=True,help="derived JSON metadata")
    ns=ap.parse_args()
    fs=Path(ns.jffs2_image).read_bytes()
    blob,meta=extract_path(fs,ns.path)
    Path(ns.output).write_bytes(blob)
    Path(ns.metadata).write_text(json.dumps(meta,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:meta[k] for k in (
        "path","inode","raw_inode_node_count","crc_valid_inode_node_count",
        "compression_types","final_size","final_sha256"
    )},indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
