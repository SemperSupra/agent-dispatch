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
    def test_verify_selector1_dataflow_anchor(self):
        handler = """
   37eac: e5d41008 ldrb r1, [r4, #8]
   37eb0: e5d48009 ldrb r8, [r4, #9]
   37eb4: e5d4c011 ldrb r12, [r4, #17]
   37ebc: e5d4200a ldrb r2, [r4, #10]
   37ec0: e5d46010 ldrb r6, [r4, #16]
   37ec4: e1800408 orr r0, r0, r8, lsl #8
   37ec8: e5d45012 ldrb r5, [r4, #18]
   37ecc: e5d4300b ldrb r3, [r4, #11]
   37ed0: e186140c orr r1, r6, r12, lsl #8
   37ed4: e5d47013 ldrb r7, [r4, #19]
   37ed8: e1800802 orr r0, r0, r2, lsl #16
   37edc: e1811805 orr r1, r1, r5, lsl #16
   37ee0: e1800c03 orr r0, r0, r3, lsl #24
   37ee4: e1811c07 orr r1, r1, r7, lsl #24
   37ee8: ea00020f b 0x3872c
"""
        tail = """
   3872c: e5801000 str r1, [r0]
"""
        v = mod.verify_disassembly(handler, tail)
        self.assertTrue(v["anchors"]["selector1_address_value"])
        self.assertTrue(v["anchors"]["selector1_store32"])

    def test_selector0_cap(self):
        with self.assertRaises(ValueError):
            mod.execute(mod.make_request(0x1000,65,0),read32=lambda a:0)

if __name__=="__main__":
    unittest.main()
