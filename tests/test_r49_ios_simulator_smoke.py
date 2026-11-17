import unittest
import struct
from scripts.r49_ios_simulator_smoke import png_dimensions, assess, receipt

class SimulatorPolicy(unittest.TestCase):
    def test_png_oracle(self):
        valid=(b"\x89PNG\r\n\x1a\n"+b"\x00\x00\x00\x0dIHDR"+
               struct.pack(">II",1170,2532))
        self.assertEqual(png_dimensions(valid),(1170,2532))
        self.assertIsNone(png_dimensions(b"not-a-png"))
        self.assertIsNone(png_dimensions(valid[:20]))
        self.assertIsNone(png_dimensions(valid[:16]+struct.pack(">II",0,20)))
    def test_all_three_guest_primitives_required(self):
        for booted,home,spawn,png,expected in [
            (True,True,True,(1170,2532),True),
            (False,True,True,(1170,2532),False),
            (True,False,True,(1170,2532),False),
            (True,True,False,(1170,2532),False),
            (True,True,True,None,False),
        ]:
            with self.subTest(booted=booted,home=home,spawn=spawn,png=png):
                self.assertEqual(assess(booted,home,spawn,png)[0],expected)
    def test_simulator_receipt_never_claims_physical_iphone_or_app(self):
        r=receipt("SUPPORTED","SIMULATOR_ONLY",{"guest_spawn":"PASS"})
        self.assertEqual(r["ios_app_install_launch_background_and_mdm"],"NOT_TESTED")
        self.assertEqual(r["physical_iphone_thermal_radio_secure_enclave"],"NOT_TESTED")
        self.assertEqual(r["parent"],"PUBLIC_GHA_MACOS_CORESIMULATOR_NOT_PHYSICAL_IOS")
