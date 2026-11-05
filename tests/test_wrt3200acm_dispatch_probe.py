#!/usr/bin/env python3
import importlib.util
import unittest
from pathlib import Path

SCRIPT=Path(__file__).resolve().parents[1]/"scripts"/"wrt3200acm_dispatch_probe.py"
spec=importlib.util.spec_from_file_location("dispatch_probe",SCRIPT)
mod=importlib.util.module_from_spec(spec); assert spec.loader; spec.loader.exec_module(mod)

class DispatchProbeTests(unittest.TestCase):
    def test_loaded_and_direct_cases(self):
        text="""
000364d8: e301e101 movw lr, #0x1101
000364dc: e15c000e cmp r12, lr
000364e0: 0a00057d beq 00036edc
00036568: e300010a movw r0, #0x10a
0003656c: e05c0000 subs r0, r12, r0
00036570: 0a000504 beq 00037984
00036580: e35c001f cmp r12, #31
"""
        ins=mod.parse_instructions(text)
        commands={0x1101:"HOSTCMD_CMD_AP_BEACON",0x010a:"HOSTCMD_CMD_SET_RF_CHANNEL"}
        cases=mod.recover_cases(ins,commands)
        got={(c["value"],c["branch_target"]) for c in cases}
        self.assertIn((0x1101,0x36edc),got)
        self.assertIn((0x010a,0x37984),got)

if __name__=="__main__":
    unittest.main()
