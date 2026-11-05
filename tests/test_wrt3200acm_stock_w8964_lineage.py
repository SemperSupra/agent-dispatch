#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_stock_w8964_lineage.py"
spec=importlib.util.spec_from_file_location("lineage",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class LineageTests(unittest.TestCase):
    def test_compare_identical(self):
        x=b"abc"
        r=mod.compare(x,x)
        self.assertEqual(r["changed_byte_count"],0)

    def test_history_order(self):
        self.assertEqual(mod.HISTORY[0][2],"9.3.2.12")
        self.assertEqual(mod.HISTORY[-1][2],"7.8.0.3")

if __name__=="__main__":
    unittest.main()
