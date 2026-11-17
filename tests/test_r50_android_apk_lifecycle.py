import unittest
from scripts.r50_android_apk_lifecycle import package_oracle

class NativeAndroidAPKLifecycleContract(unittest.TestCase):
    def test_independent_observation_requires_verified_app_sandbox_and_resumed_ui(self):
        cases=[
            ("<string name='status'>R50_LAUNCHED</string><int name='android_api' value='35'/>",True,True,True,True),
            ("",True,True,True,False),
            ("R50_LAUNCHED",True,True,True,False),
            ("<int name='android_api' value='35'/>",True,True,True,False),
            ("R50_LAUNCHED android_api",False,True,True,False),
            ("R50_LAUNCHED android_api",True,False,True,False),
            ("R50_LAUNCHED android_api",True,True,False,False),
        ]
        for prefs,resumed,installed,signed,expected in cases:
            with self.subTest(prefs=prefs,resumed=resumed,installed=installed,signed=signed):
                self.assertEqual(package_oracle(prefs,resumed,installed,signed),expected)
    def test_existing_r49_no_probe_behavior_remains_backward_compatible(self):
        from inspect import signature
        from scripts.r49_android_companion_smoke import smoke
        self.assertIsNone(signature(smoke).parameters["live_probe"].default)
