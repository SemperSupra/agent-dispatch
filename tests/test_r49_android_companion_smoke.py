import unittest
from scripts.r49_android_companion_smoke import decide, safe_result

class AndroidMobilePolicyTest(unittest.TestCase):
    def test_all_independent_observations_required(self):
        cases=[
            ("x86_64","35",True,True,73,True),
            ("arm64-v8a","35",True,True,73,False),
            ("x86_64","36",True,True,73,False),
            ("x86_64","35",False,True,73,False),
            ("x86_64","35",True,False,73,False),
            ("x86_64","35",True,True,100,False),
            ("x86_64","35",True,True,None,False),
        ]
        for abi,api,started,foreground,battery,expected in cases:
            with self.subTest(abi=abi,api=api,started=started,foreground=foreground,battery=battery):
                self.assertEqual(decide(abi,api,started,foreground,battery)[0],expected)

    def test_receipt_cannot_claim_phone_capability(self):
        r=safe_result({"observed_api":"35"},"SUPPORTED","ANDROID_EMULATOR_ORACLE_PASS")
        self.assertEqual(r["parent"],"PUBLIC_GHA_ANDROID_API35_X64_NOT_PHYSICAL_DEVICE")
        self.assertEqual(r["physical_phone_security_thermal_radio_background"],"NOT_TESTED")
        self.assertEqual(r["android_app_background_or_device_owner"],"NOT_TESTED")
