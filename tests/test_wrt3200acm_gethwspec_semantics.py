#!/usr/bin/env python3
import importlib.util
import struct
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_gethwspec_semantics.py"
spec=importlib.util.spec_from_file_location("gethw",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class GetHwSpecTests(unittest.TestCase):
    def test_broadcast_mac_returns_internal_and_fixed_fields(self):
        req=mod.make_request(fw_awake_cookie=0x1000)
        out,meta=mod.partial_rehost(req,internal_mac=bytes.fromhex("001122334455"),region_code=0x10,num_mcast_addr=32,host_if=5)
        self.assertEqual(out[14:20],bytes.fromhex("001122334455"))
        self.assertEqual(out[8],7)
        self.assertEqual(out[9],5)
        self.assertEqual(struct.unpack_from("<H",out,12)[0],32)
        self.assertEqual(struct.unpack_from("<H",out,20)[0],0x10)
        self.assertEqual(struct.unpack_from("<H",out,22)[0],3)
        self.assertEqual(struct.unpack_from("<I",out,24)[0],0x0903020c)
        self.assertEqual(struct.unpack_from("<I",out,28)[0],0x2000)
        self.assertEqual(out[40]&1,1)
        self.assertTrue(meta["unknown_fields"]["post_fill_helper_0x3b038_effects"])

    def test_nonbroadcast_mac_records_state_change(self):
        req=mod.make_request(bytes.fromhex("aabbccddeeff"))
        out,meta=mod.partial_rehost(req,internal_mac=bytes.fromhex("001122334455"),region_code=1,num_mcast_addr=2,host_if=3)
        self.assertEqual(out[14:20],bytes.fromhex("aabbccddeeff"))
        self.assertEqual(meta["state_change"]["internal_mac"],"aa:bb:cc:dd:ee:ff")

if __name__=="__main__":
    unittest.main()
