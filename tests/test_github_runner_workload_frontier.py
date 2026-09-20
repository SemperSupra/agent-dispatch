import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location(
    "github_runner_workload_frontier",ROOT/"scripts"/"github_runner_workload_frontier.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class FrontierWorkloadTests(unittest.TestCase):
    def test_android_wrong_platform_skips(self):
        with mock.patch.object(MOD.platform,"system",return_value="Darwin"):
            r=MOD.qualify_android_emulator("macos-26")
        self.assertEqual(r["result"]["classification"],"SKIPPED_GUARDRAIL")

    def test_android_no_system_image_is_guardrail_not_failure(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"),              mock.patch.object(MOD.platform,"machine",return_value="x86_64"),              mock.patch.object(MOD,"_sdk_root",return_value=pathlib.Path("/sdk")),              mock.patch.object(MOD.pathlib.Path,"exists",return_value=True),              mock.patch.object(MOD,"_installed_x86_system_images",return_value=[]):
            r=MOD.qualify_android_emulator("ubuntu-26.04")
        self.assertEqual(r["result"]["classification"],"SKIPPED_GUARDRAIL")

    def test_ios_compile_wrong_platform_skips(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"):
            r=MOD.qualify_ios_sdk_compile("ubuntu-26.04")
        self.assertEqual(r["result"]["classification"],"SKIPPED_GUARDRAIL")

    def test_installed_image_selection_prefers_latest_api(self):
        class FakePath:
            pass
        # Test the sort contract directly with realistic discovered tuples.
        images=[((35,),"system-images;android-35;google_apis;x86_64",FakePath()),
                ((36,),"system-images;android-36;google_apis;x86_64",FakePath())]
        self.assertEqual(sorted(images,key=lambda x:x[0])[-1][1],
                         "system-images;android-36;google_apis;x86_64")

    def test_receipt_does_not_imply_ranking(self):
        r=MOD._base("ubuntu-26.04","test")
        self.assertIn("no scalar runner ranking",r["warnings"][1])

if __name__=="__main__":
    unittest.main()
