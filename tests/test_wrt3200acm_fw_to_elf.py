#!/usr/bin/env python3
import importlib.util, struct, tempfile, unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_fw_to_elf.py"
spec=importlib.util.spec_from_file_location("fwelf",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class ConverterTests(unittest.TestCase):
    def test_two_ranges(self):
        def rec(addr,payload):
            size=len(payload)+4
            return struct.pack("<IIII",1,addr,size,0x1234)+payload+b"CHK!"
        data=rec(0,b"AAAA")+rec(4,b"BBBB")+rec(0xd4800000,b"CCCC")+struct.pack("<IIII",4,0,0,0)
        rs=mod.parse_records(data)
        ranges=mod.merge_ranges(rs)
        self.assertEqual([(r["address"],bytes(r["data"])) for r in ranges],[(0,b"AAAABBBB"),(0xd4800000,b"CCCC")])
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x.elf"; mod.write_elf(p,ranges)
            h=p.read_bytes()[:20]
            self.assertEqual(h[:4],b"\x7fELF")
            self.assertEqual(struct.unpack_from("<H",h,18)[0],40)

if __name__=="__main__":
    unittest.main()
