#!/usr/bin/env python3
"""Strict DEX fixture adapter for the neutral Androguard paired interview."""
import argparse
from pathlib import Path
import hashlib
import struct
import sys
import zlib
import re_tool_androguard_parity as experiment

def complete_map(data):
    b=bytearray(data)
    count=struct.unpack_from("<I",b,0x60)[0]
    string_off=struct.unpack_from("<I",b,0x3c)[0]
    type_off=struct.unpack_from("<I",b,0x44)[0]
    class_off=struct.unpack_from("<I",b,0x64)[0]
    data_off=struct.unpack_from("<I",b,0x6c)[0]
    b.extend(bytes((-len(b))%4))
    map_off=len(b)
    rows=((0,1,0),(1,count,string_off),(2,count,type_off),
          (6,count,class_off),(0x2002,count,data_off),(0x1000,1,map_off))
    b.extend(struct.pack("<I",len(rows)))
    for kind,size,off in rows:
        b.extend(struct.pack("<HHII",kind,0,size,off))
    struct.pack_into("<III",b,0x20,len(b),0x70,0x12345678)
    struct.pack_into("<I",b,0x34,map_off)
    struct.pack_into("<I",b,0x68,len(b)-data_off)
    b[12:32]=hashlib.sha1(b[32:]).digest()
    struct.pack_into("<I",b,8,zlib.adler32(b[12:]) & 0xffffffff)
    return bytes(b)

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--asc",type=Path,required=True)
    parser.add_argument("--and-source",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    experiment.canonical_checksum=complete_map
    sys.exit(experiment.main(args))
