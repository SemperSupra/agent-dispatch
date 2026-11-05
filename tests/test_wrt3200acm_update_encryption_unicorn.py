#!/usr/bin/env python3
import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_update_encryption_unicorn.py"
spec=importlib.util.spec_from_file_location("updenc_uc",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class UpdateEncryptionBoundaryTests(unittest.TestCase):
    def test_enable_request_layout(self):
        b=mod.make_enable(6,macid=7)
        self.assertEqual(struct.unpack_from("<I",b,8)[0],0)
        self.assertEqual(b[5],7)
        self.assertEqual(b[22],6)

    def test_key_request_layout(self):
        b=mod.make_key(3,0x0102,0x12345678,0x0110,macid=9)
        self.assertEqual(struct.unpack_from("<I",b,8)[0],3)
        self.assertEqual(struct.unpack_from("<H",b,18)[0],0x0102)
        self.assertEqual(struct.unpack_from("<I",b,24)[0],0x12345678)
        self.assertEqual(struct.unpack_from("<H",b,28)[0],0x0110)
        self.assertEqual(len(b),80)

    def test_enable_map_known_host_modes(self):
        self.assertEqual(mod.ENABLE_MAP[0],1)
        self.assertEqual(mod.ENABLE_MAP[1],0)
        self.assertEqual(mod.ENABLE_MAP[4],3)
        self.assertEqual(mod.ENABLE_MAP[6],4)
        self.assertEqual(mod.ENABLE_MAP[7],4)

if __name__=="__main__":
    unittest.main()
