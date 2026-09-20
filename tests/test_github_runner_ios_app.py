import importlib.util,pathlib,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("ios_app",ROOT/"scripts"/"github_runner_ios_app.py")
MOD=importlib.util.module_from_spec(SPEC);assert SPEC.loader;SPEC.loader.exec_module(MOD)
class Tests(unittest.TestCase):
    def test_wrong_platform_skips(self):
        with mock.patch.object(MOD.platform,"system",return_value="Linux"):
            # Avoid writing by use temp output.
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                with mock.patch("sys.argv",["x","--label","ubuntu-26.04","--out",td+"/r.json"]):
                    self.assertEqual(MOD.main(),0)
                    import json
                    r=json.loads(pathlib.Path(td+"/r.json").read_text())
                    self.assertEqual(r["result"]["classification"],"SKIPPED_GUARDRAIL")
    def test_bundle_id_is_stable(self):
        self.assertEqual(MOD.BUNDLE_ID,"com.sempersupra.runnerfrontier")
if __name__=="__main__":unittest.main()
