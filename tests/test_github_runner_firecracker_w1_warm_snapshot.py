import importlib.util
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("w1",ROOT/"scripts"/"github_runner_firecracker_w1_warm_snapshot.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class W1Tests(unittest.TestCase):
    def test_expected_digest_is_stable(self):
        a=MOD.expected_digest(); b=MOD.expected_digest()
        self.assertEqual(a,b)
        self.assertEqual(len(a),64)

    def test_initramfs_has_root_and_scratch_block_nodes(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); init=root/"init"; out=root/"initrd"
            init.write_bytes(b"x")
            MOD._build_initramfs(init,out)
            data=out.read_bytes()
            self.assertIn(b"dev/vda\0",data)
            self.assertIn(b"dev/vdb\0",data)

if __name__=="__main__":
    unittest.main()
