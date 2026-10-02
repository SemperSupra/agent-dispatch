#!/usr/bin/env python3
import importlib.util
import struct
import unittest
import zlib
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"jffs2_target_extract.py"
spec=importlib.util.spec_from_file_location("jx",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

def inode_node(ino,version,isize,offset,payload,compr=0,dsize=None):
    if dsize is None: dsize=len(payload)
    prefix=struct.pack("<HHI",0x1985,0xe002,68+len(payload))
    hdr_crc=mod.crc32_raw(prefix)
    hdr=prefix+struct.pack("<I",hdr_crc)
    hdr+=struct.pack("<IIIHHIIIIII",ino,version,0o100644,0,0,isize,0,0,0,offset,len(payload),dsize)
    hdr+=bytes([compr,compr])+struct.pack("<H",0)
    data_crc=mod.crc32_raw(payload)
    node_crc=mod.crc32_raw(hdr)
    raw=hdr+struct.pack("<II",data_crc,node_crc)+payload
    return raw+b"\xff"*((4-len(raw)%4)%4)

class Jffs2TargetExtractTests(unittest.TestCase):
    def test_raw_crc_known(self):
        self.assertEqual(mod.crc32_raw(b"123456789"),0x2dfd2d88)

    def test_replay_fragmented_inode(self):
        n1=inode_node(7,1,8,0,b"ABCD")
        n2=inode_node(7,2,8,4,b"EFGH")
        rows=mod.parse_inode_nodes(n1+n2,7)
        blob,meta=mod.reconstruct_inode(rows)
        self.assertEqual(blob,b"ABCDEFGH")
        self.assertEqual(meta["crc_valid_inode_node_count"],2)

    def test_rtime_literal(self):
        self.assertEqual(mod.rtime_decompress(bytes([65,0,66,0]),2),b"AB")

if __name__=="__main__":
    unittest.main()
