import importlib.util, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("u",ROOT/"scripts"/"github_runner_userland_census.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class T(unittest.TestCase):
    def test_os_release(self):
        self.assertEqual(MOD.parse_os_release('ID=debian\nVERSION_ID="13"\nSECRET=x\n'),{"ID":"debian","VERSION_ID":"13"})
    def test_libc(self):
        self.assertEqual(MOD.detect_libc("musl libc")["family"],"musl")
        self.assertEqual(MOD.detect_libc("GNU libc 2.41")["family"],"glibc")
    def test_sections(self):
        v,s=MOD.parse_sections("A=1\nOS_RELEASE_BEGIN\nID=alpine\nOS_RELEASE_END\n")
        self.assertEqual(v["A"],"1"); self.assertEqual(s["OS_RELEASE"],"ID=alpine")
if __name__=="__main__": unittest.main()
