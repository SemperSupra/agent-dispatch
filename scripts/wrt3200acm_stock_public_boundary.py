#!/usr/bin/env python3
"""Characterize the representation boundary between OEM-stock and public 88W8964 firmware.

Firmware bytes remain ephemeral. Durable output is hashes, record-header metadata,
block equality/entropy, and compression-signature/probe results only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import zlib
import lzma
from pathlib import Path
from typing import Any

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts=[0]*256
    for b in data: counts[b]+=1
    e=0.0
    for c in counts:
        if c:
            p=c/len(data)
            e-=p*math.log2(p)
    return round(e,6)

def longest_common_prefix(a: bytes,b: bytes)->int:
    n=min(len(a),len(b))
    lo=0
    while lo<n and a[lo]==b[lo]: lo+=1
    return lo

def longest_common_suffix(a: bytes,b: bytes)->int:
    n=min(len(a),len(b)); i=0
    while i<n and a[len(a)-1-i]==b[len(b)-1-i]: i+=1
    return i

def record_prefix(data: bytes, cap:int=64)->dict[str,Any]:
    off=0; rows=[]; termination="cap"
    for _ in range(cap):
        if off+16>len(data):
            termination="eof"; break
        typ,addr,size,checksum=struct.unpack_from("<IIII",data,off)
        row={
            "index":len(rows),"file_offset":off,"type":typ,
            "load_address":addr,"load_size":size,"checksum_field":checksum
        }
        if typ==4:
            row["meaning"]="end"; rows.append(row); off+=16; termination="type4-end"; break
        if typ==6:
            row["meaning"]="split"; rows.append(row); off+=16; continue
        if typ!=1:
            row["meaning"]="unknown-type"; rows.append(row); termination="unknown-type"; break
        if size<4 or off+16+size>len(data):
            row["meaning"]="invalid-size"; rows.append(row); termination="invalid-size"; break
        payload=data[off+16:off+16+size-4]
        trailer=data[off+16+size-4:off+16+size]
        row.update({
            "meaning":"load","payload_size":len(payload),"payload_sha256":sha256(payload),
            "trailer_hex":trailer.hex(),"next_offset":off+16+size
        })
        rows.append(row); off+=16+size
    return {"termination":termination,"consumed_bytes":off,"records":rows}

def block_profile(a: bytes,b: bytes,block:int=4096)->list[dict[str,Any]]:
    out=[]
    n=max(len(a),len(b))
    for off in range(0,n,block):
        aa=a[off:off+block]; bb=b[off:off+block]
        m=min(len(aa),len(bb))
        equal=sum(1 for i in range(m) if aa[i]==bb[i])
        out.append({
            "offset":off,
            "size_stock":len(aa),"size_public":len(bb),
            "equal_byte_count":equal,
            "equal_fraction":round(equal/max(len(aa),len(bb),1),6),
            "stock_entropy":entropy(aa),
            "public_entropy":entropy(bb),
            "stock_zero_fraction":round(aa.count(0)/max(len(aa),1),6),
            "public_zero_fraction":round(bb.count(0)/max(len(bb),1),6),
            "stock_sha256":sha256(aa) if aa else None,
            "public_sha256":sha256(bb) if bb else None,
        })
    return out

def compression_probes(data:bytes,offset:int)->list[dict[str,Any]]:
    # Probe only standard formats at/near the observed transition; no brute force.
    candidates=sorted(set([max(0,offset-16),offset,max(0,offset-1),((offset+3)//4)*4,4096,4224]))
    results=[]
    for off in candidates:
        if off>=len(data): continue
        chunk=data[off:]
        for kind in ("zlib","gzip","xz","lzma-alone"):
            ok=False; out_len=None; error=None
            try:
                if kind=="zlib":
                    dec=zlib.decompress(chunk)
                elif kind=="gzip":
                    dec=zlib.decompress(chunk,16+zlib.MAX_WBITS)
                elif kind=="xz":
                    dec=lzma.decompress(chunk,format=lzma.FORMAT_XZ)
                else:
                    dec=lzma.decompress(chunk,format=lzma.FORMAT_ALONE)
                ok=True; out_len=len(dec)
            except Exception as exc:
                error=type(exc).__name__
            results.append({"offset":off,"kind":kind,"ok":ok,"output_size":out_len,"error":error})
    return results

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("stock")
    ap.add_argument("public")
    ap.add_argument("--out",required=True)
    ns=ap.parse_args()
    stock=Path(ns.stock).read_bytes(); public=Path(ns.public).read_bytes()
    lcp=longest_common_prefix(stock,public)
    lcs=longest_common_suffix(stock,public)
    stock_rec=record_prefix(stock)
    public_rec=record_prefix(public)
    profile=block_profile(stock,public)
    report={
        "schema":"wrt8964-stock-public-representation-boundary/v1",
        "stock":{"size":len(stock),"sha256":sha256(stock),"entropy":entropy(stock)},
        "public":{"size":len(public),"sha256":sha256(public),"entropy":entropy(public)},
        "longest_common_prefix_bytes":lcp,
        "longest_common_suffix_bytes":lcs,
        "first_divergence_offset":lcp if lcp<min(len(stock),len(public)) else None,
        "stock_record_prefix":stock_rec,
        "public_record_prefix":public_rec,
        "block_size":4096,
        "block_profile":profile,
        "stock_compression_probes":compression_probes(stock,lcp),
        "public_compression_probes":compression_probes(public,lcp),
        "interpretation_guardrail":"Entropy and failed standard decompression can distinguish representation classes but do not prove encryption or proprietary compression."
    }
    Path(ns.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({
        "stock":report["stock"],"public":report["public"],
        "longest_common_prefix_bytes":lcp,"longest_common_suffix_bytes":lcs,
        "stock_record_termination":stock_rec["termination"],
        "public_record_termination":public_rec["termination"],
        "first_blocks":profile[:4],
        "stock_successful_compression_probes":[x for x in report["stock_compression_probes"] if x["ok"]],
    },indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
