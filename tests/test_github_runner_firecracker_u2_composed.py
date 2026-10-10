import importlib.util, hashlib, pathlib, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("u2",ROOT/"scripts"/"github_runner_firecracker_u2_composed.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class U2Tests(unittest.TestCase):
    def test_payload(self):
        self.assertEqual(MOD.PAYLOAD_SHA256,hashlib.sha256(MOD.PAYLOAD).hexdigest())
    def test_initramfs_contains_probe_and_resolver(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td);init=root/"init";probe=root/"u2.py";out=root/"initrd"
            init.write_bytes(b"i");probe.write_text("print('x')")
            MOD._build_initramfs(init,probe,out)
            data=out.read_bytes()
            self.assertIn(b"work/u2.py\0",data)
            self.assertIn(b"work/resolv.conf\0",data)
            self.assertIn(b"nameserver 1.1.1.1",data)
if __name__=="__main__":unittest.main()
