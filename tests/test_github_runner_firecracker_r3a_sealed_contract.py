import importlib.util
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r3a",ROOT/"scripts"/"github_runner_firecracker_r3a_sealed_contract.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)

class R3aTests(unittest.TestCase):
    def test_native_contract_is_real_and_passes(self):
        result=MOD._native_contract()
        self.assertEqual(result["exit_code"],0)
        self.assertTrue(result["ok_marker"])
        self.assertGreater(result["tests_run"],0)

    def test_initramfs_has_two_block_nodes(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); init=root/"init"; out=root/"initrd"
            init.write_bytes(b"x")
            MOD._build_initramfs(init,out)
            data=out.read_bytes()
            self.assertIn(b"dev/vda\0",data)
            self.assertIn(b"dev/vdb\0",data)

if __name__=="__main__":unittest.main()
