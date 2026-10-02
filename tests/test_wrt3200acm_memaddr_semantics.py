#!/usr/bin/env python3
import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_memaddr_semantics.py"
spec=importlib.util.spec_from_file_location("memaddr",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class MemAddrRehostTests(unittest.TestCase):
    def test_selector0_reads_sequential_dwords(self):
        req=mod.make_request(0x1000,3)
        mem={0x1000:0x11223344,0x1004:0xaabbccdd,0x1008:0x01020304}
        out=mod.execute_selector0(req,lambda a:mem[a])
        self.assertEqual(struct.unpack_from("<III",out,16),(0x11223344,0xaabbccdd,0x01020304))

    def test_zero_length_performs_no_reads(self):
        req=mod.make_request(0x1000,0)
        seen=[]
        mod.execute_selector0(req,lambda a:seen.append(a) or 0)
        self.assertEqual(seen,[])

    def test_length_cap(self):
        req=mod.make_request(0x1000,65)
        with self.assertRaises(ValueError):
            mod.execute_selector0(req,lambda a:0)

    def test_unknown_selector_fails_closed(self):
        req=mod.make_request(0x1000,1,selector=1)
        with self.assertRaises(mod.UnknownSelector):
            mod.execute_selector0(req,lambda a:0)

if __name__=="__main__":
    unittest.main()
