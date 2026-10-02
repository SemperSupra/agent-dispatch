#!/usr/bin/env python3
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_ghidra_prep.py"
spec=importlib.util.spec_from_file_location("prep",SCRIPT)
mod=importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(mod)

class PrepTests(unittest.TestCase):
    def test_record_reconstruction_and_elf(self):
        payload1=b"ABCDEFGH"
        payload2=b"IJKL"
        r1=struct.pack("<IIII",1,0x1000,len(payload1)+4,0)+payload1+b"1234"
        r2=struct.pack("<IIII",1,0x1008,len(payload2)+4,0)+payload2+b"5678"
        end=struct.pack("<IIII",4,0,0,0)
        data=r1+r2+end
        recs=mod.parse_records(data)
        segs=mod.reconstruct_segments(data,recs)
        self.assertEqual(len(segs),1)
        self.assertEqual(segs[0]["start"],0x1000)
        self.assertEqual(bytes(segs[0]["data"]),payload1+payload2)
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x.elf"
            mod.write_elf32_arm(p,segs)
            b=p.read_bytes()
            self.assertEqual(b[:4],b"\x7fELF")
            self.assertEqual(struct.unpack_from("<H",b,18)[0],40)

if __name__=="__main__":
    unittest.main()
