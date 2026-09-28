import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("w3",ROOT/"scripts"/"github_runner_firecracker_w3_post_restore_reset.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class W3Tests(unittest.TestCase):
    def test_work_digest_depends_on_reset_identity(self):
        a=MOD._expected_work_digest("aa","bb")
        b=MOD._expected_work_digest("aa","bc")
        self.assertEqual(len(a),64)
        self.assertNotEqual(a,b)

    def test_guest_source_places_reset_after_template_ready(self):
        source=(ROOT/"experiments/firecracker/guest/w3-post-restore-reset.py").read_text()
        self.assertLess(source.index("FIRECRACKER_W3_TEMPLATE_READY"),source.index("random.seed"))
        self.assertLess(source.index("random.seed"),source.index("FIRECRACKER_W3_RESET"))

if __name__=="__main__":
    unittest.main()
