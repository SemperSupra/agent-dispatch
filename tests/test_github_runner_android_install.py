import importlib.util,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("android_install",ROOT/"scripts"/"github_runner_android_install.py")
MOD=importlib.util.module_from_spec(SPEC);assert SPEC.loader;SPEC.loader.exec_module(MOD)
class Tests(unittest.TestCase):
    def test_package_set_is_bounded(self):
        self.assertEqual(MOD.PKGS,["emulator","system-images;android-35;google_apis;x86_64"])
if __name__=="__main__":unittest.main()
