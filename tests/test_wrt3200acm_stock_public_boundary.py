#!/usr/bin/env python3
import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_stock_public_boundary.py"
spec=importlib.util.spec_from_file_location("boundary",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class BoundaryTests(unittest.TestCase):
    def test_prefix_suffix(self):
        self.assertEqual(mod.longest_common_prefix(b"abcX",b"abcY"),3)
        self.assertEqual(mod.longest_common_suffix(b"Xabc",b"Yabc"),3)

    def test_record_prefix_stops_unknown(self):
        payload=b"A"*508
        rec=struct.pack("<IIII",1,0,512,0)+payload+b"TAIL"
        bad=struct.pack("<IIII",0x12345678,0,0,0)
        r=mod.record_prefix(rec+bad)
        self.assertEqual(r["records"][0]["meaning"],"load")
        self.assertEqual(r["records"][1]["meaning"],"unknown-type")

if __name__=="__main__":
    unittest.main()
