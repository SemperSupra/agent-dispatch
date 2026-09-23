import importlib.util, pathlib, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r2",ROOT/"scripts"/"github_runner_firecracker_r2_network.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class R2Tests(unittest.TestCase):
    def test_counter_parser(self):
        text='ip daddr 169.254.0.0/16 counter packets 3 bytes 180 drop'
        self.assertEqual(MOD._counter_for(text,"169.254.0.0/16"),3)
    def test_initramfs_includes_ca(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            init=root/"init"; cand=root/"candidate"; ca=root/"ca"; out=root/"initrd"
            init.write_bytes(b"i"); cand.write_bytes(b"c"); ca.write_bytes(b"cert")
            MOD._build_initramfs(init,cand,ca,out)
            data=out.read_bytes()
            self.assertIn(b"etc/ssl/certs/ca-certificates.crt\0",data)
if __name__=="__main__": unittest.main()
