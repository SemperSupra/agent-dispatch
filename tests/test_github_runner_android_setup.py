import importlib.util, pathlib, unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("android_setup",ROOT/"scripts"/"github_runner_android_setup.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class AndroidSetupTests(unittest.TestCase):
    def test_wrong_platform_skips(self):
        with mock.patch.object(MOD.platform,"system",return_value="Darwin"):
            r=MOD.inventory("macos-26")
        self.assertEqual(r["result"]["classification"],"SKIPPED_GUARDRAIL")

    def test_missing_sdk_is_negative_observation(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"),              mock.patch.object(MOD.platform,"machine",return_value="x86_64"),              mock.patch.object(MOD.pathlib.Path,"is_dir",return_value=False):
            r=MOD.inventory("ubuntu-26.04")
        self.assertEqual(r["result"]["classification"],"NEGATIVE_OBSERVATION")

    def test_system_image_package_shape(self):
        parts=("android-36","google_apis","x86_64")
        self.assertEqual("system-images;"+";".join(parts),
                         "system-images;android-36;google_apis;x86_64")

if __name__=="__main__": unittest.main()
