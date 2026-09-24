import importlib.util
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("w2",ROOT/"scripts"/"github_runner_firecracker_w2_clone_state.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class W2Tests(unittest.TestCase):
    def test_compare_clone_state(self):
        a={"session":"aa","py_random":"bb","urandom":"cc","secrets":"dd"}
        b={"session":"aa","py_random":"bb","urandom":"ee","secrets":"ff"}
        result=MOD.compare_clone_state(a,b)
        self.assertTrue(result["pre_snapshot_session_duplicated"])
        self.assertTrue(result["python_prng_output_duplicated"])
        self.assertTrue(result["kernel_urandom_unique"])
        self.assertTrue(result["secrets_token_unique"])

    def test_initramfs_has_two_block_nodes(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); init=root/"init"; out=root/"initrd"
            init.write_bytes(b"x")
            MOD._build_initramfs(init,out)
            data=out.read_bytes()
            self.assertIn(b"dev/vda\0",data)
            self.assertIn(b"dev/vdb\0",data)

if __name__=="__main__":
    unittest.main()
