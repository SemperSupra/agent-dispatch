#!/usr/bin/env python3
import importlib.util
import struct
import unittest
import zlib
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_jffs2_inventory.py"
spec=importlib.util.spec_from_file_location("jinv",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

def dirent(pino,version,ino,dtype,name):
    nb=name.encode()
    tot=40+len(nb)
    prefix=struct.pack("<HHI",0x1985,0xe001,tot)
    hdr_crc=zlib.crc32(prefix)&0xffffffff
    fixed=prefix+struct.pack("<I",hdr_crc)+struct.pack("<IIII",pino,version,ino,0)+bytes([len(nb),dtype])+b"\x00\x00"
    node_crc=0
    name_crc=zlib.crc32(nb)&0xffffffff
    raw=fixed+struct.pack("<II",node_crc,name_crc)+nb
    return raw+b"\xff"*((4-len(raw)%4)%4)

class Jffs2InventoryTests(unittest.TestCase):
    def test_paths_and_tombstone(self):
        data=dirent(1,1,2,4,"lib")+dirent(2,1,3,4,"firmware")+dirent(3,1,4,8,"88W8964.bin")
        p=mod.parse_nodes(data,0)
        self.assertEqual(p["valid_header_crc_count"],3)
        active=mod.active_dirents(p["dirents"])
        paths=mod.build_paths(active)
        self.assertIn("/lib/firmware/88W8964.bin",{x["path"] for x in paths})

if __name__=="__main__":
    unittest.main()
