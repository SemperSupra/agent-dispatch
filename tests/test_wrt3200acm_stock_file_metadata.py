#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_stock_file_metadata.py"
spec=importlib.util.spec_from_file_location("stockmeta",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class StockMetadataTests(unittest.TestCase):
    def test_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x"
            p.write_bytes(b"abc")
            self.assertEqual(mod.sha256(p),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_default_target_contains_w8964(self):
        self.assertIn("/lib/modules/3.10.70/W8964.bin",mod.DEFAULT_PATHS)

if __name__=="__main__":
    unittest.main()
