#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_update_encryption_semantics.py"
spec=importlib.util.spec_from_file_location("updenc",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class UpdateEncryptionTests(unittest.TestCase):
    def test_dispatch_derivation(self):
        text="""
   364d8: e301e101 movw lr, #4353 @ 0x1101
   364e0: e04c200e sub r2, r12, lr
   36638: e3520021 cmp r2, #33 @ 0x21
   3663c: 0a000550 beq 0x37b84
"""
        self.assertTrue(mod.verify_dispatch(text)["all_required_present"])

    def test_wrapper(self):
        text="""
   37b84: e59f0808 ldr r0, [pc, #2056] @ 0x38394
   37b88: e1a01004 mov r1, r4
   37b8c: ebffa835 bl 0x21c68
   37b90: ea0004af b 0x38e54
"""
        self.assertTrue(mod.verify_wrapper(text)["all_required_present"])

    def test_host_layout(self):
        self.assertEqual(mod.HOST_LAYOUT["set_key_form"]["key_param"]["mac_addr"]["offset"],74)
        self.assertEqual(mod.HOST_LAYOUT["set_key_form"]["packed_size"],80)
        self.assertEqual(mod.HOST_LAYOUT["action_type"]["3"],"SET_GROUP_KEY")

if __name__=="__main__":
    unittest.main()
