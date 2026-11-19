import plistlib
import unittest
from pathlib import Path
from scripts.r50_ios_xcode_app_lifecycle import launched_from_sandbox

ROOT=Path(__file__).resolve().parents[1]/"tools"/"r50-ios-app"

class XcodeCompanionContract(unittest.TestCase):
    def test_real_xcode_project_and_original_source_are_present(self):
        project=(ROOT/"R50Companion.xcodeproj"/"project.pbxproj").read_text(encoding="utf-8")
        scheme=(ROOT/"R50Companion.xcodeproj"/"xcshareddata"/"xcschemes"/"R50Companion.xcscheme").read_text(encoding="utf-8")
        swift=(ROOT/"R50Companion"/"AppDelegate.swift").read_text(encoding="utf-8")
        with (ROOT/"R50Companion"/"Info.plist").open("rb") as f:info=plistlib.load(f)
        self.assertIn("PBXNativeTarget",project)
        self.assertIn("PBXSourcesBuildPhase",project)
        self.assertIn("R50Companion",scheme)
        self.assertIn("R50_IOS_APP_LAUNCHED",swift)
        self.assertEqual(info["CFBundleExecutable"],"$(EXECUTABLE_NAME)")
        self.assertNotIn("UIApplicationExitsOnSuspend",info)
        for forbidden in ("URLSession","NSCameraUsageDescription","NSMicrophoneUsageDescription","aps-environment"):
            self.assertNotIn(forbidden,swift)
            self.assertNotIn(forbidden,str(info))
    def test_private_app_state_must_be_independent_of_launch_exit(self):
        variants=[
            ("R50_IOS_APP_LAUNCHED",0,True,True,True),
            ("R50_IOS_APP_LAUNCHED",1,True,True,False),
            ("R50_IOS_APP_LAUNCHED",0,False,True,False),
            ("R50_IOS_APP_LAUNCHED",0,True,False,False),
            (None,0,True,True,False),
            ("R50_APP_MAYBE",0,True,True,False),
        ]
        for state,code,installed,container,expected in variants:
            with self.subTest(state=state,code=code,installed=installed,container=container):
                self.assertEqual(launched_from_sandbox(state,code,installed,container),expected)
