import importlib.util
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r1",ROOT/"scripts"/"github_runner_firecracker_r1_storage.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class R1Tests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(MOD.BYTES,64*1024*1024)
        self.assertEqual(MOD.IMAGE_MIB,128)
    def test_initramfs_contains_block_node_and_scratch(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); init=root/"init"; out=root/"initrd"
            init.write_bytes(b"x")
            MOD._build_initramfs(init,out)
            data=out.read_bytes()
            self.assertIn(b"dev/vda\0",data)
            self.assertIn(b"scratch\0",data)

if __name__=="__main__":unittest.main()
