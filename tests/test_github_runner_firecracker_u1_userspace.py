import importlib.util, hashlib, pathlib, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("u1",ROOT/"scripts"/"github_runner_firecracker_u1_userspace.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class U1Tests(unittest.TestCase):
    def test_payload_identity(self):
        self.assertEqual(MOD.PAYLOAD_SHA256,hashlib.sha256(MOD.PAYLOAD).hexdigest())
    def test_initramfs_has_two_block_devices_and_probe(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td); init=root/"init"; probe=root/"probe.py"; out=root/"initrd"
            init.write_bytes(b"init"); probe.write_text("print('x')")
            MOD._build_initramfs(init,probe,out)
            data=out.read_bytes()
            self.assertIn(b"dev/vda\0",data)
            self.assertIn(b"dev/vdb\0",data)
            self.assertIn(b"work/u1.py\0",data)
if __name__=="__main__": unittest.main()
