#!/usr/bin/env python3
import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_memaddr_semantics.py"
spec=importlib.util.spec_from_file_location("memaddr",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class MemAddrRehostTests(unittest.TestCase):
    def test_selector0_reads(self):
        req=mod.make_request(0x1000,2,0)
        mem={0x1000:0x11223344,0x1004:0xaabbccdd}
        out=mod.execute(req,read32=lambda a:mem[a])
        self.assertEqual(struct.unpack_from("<II",out,16),(0x11223344,0xaabbccdd))
    def test_selector1_writes(self):
        req=mod.make_request(0x2000,1,1,value0=0xdecafbad); seen={}
        mod.execute(req,write32=lambda a,v:seen.update(address=a,value=v))
        self.assertEqual(seen,{"address":0x2000,"value":0xdecafbad})
    def test_selector2_reads_256(self):
        req=mod.make_request(0x3000,0,2); block=bytes(range(256))
        out=mod.execute(req,read_block=lambda a,n:block)
        self.assertEqual(out[16:272],block)
    def test_selector3_literals(self):
        req=mod.make_request(0,0,3)
        out=mod.execute(req,selector3_values=(0x11223344,0xaabbccdd))
        self.assertEqual(struct.unpack_from("<I",out,16)[0],0x11223344)
        self.assertEqual(struct.unpack_from("<I",out,24)[0],0xaabbccdd)
    def test_selector0_cap(self):
        with self.assertRaises(ValueError):
            mod.execute(mod.make_request(0x1000,65,0),read32=lambda a:0)

if __name__=="__main__":
    unittest.main()
