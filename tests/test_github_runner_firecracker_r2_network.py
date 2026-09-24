import importlib.util, pathlib, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("r2",ROOT/"scripts"/"github_runner_firecracker_r2_network.py")
MOD=importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(MOD)
class R2Tests(unittest.TestCase):
    def test_counter_parser(self):
        nft='ip daddr 169.254.0.0/16 counter packets 3 bytes 180 drop'
        ipt='       4      264 MASQUERADE  all  --  *  eth0  192.0.2.2  0.0.0.0/0'
        self.assertEqual(MOD._counter_for(nft,"169.254.0.0/16"),3)
        self.assertEqual(MOD._counter_for(ipt,"MASQUERADE"),4)

    def test_counter_parser_aggregates_matching_rules(self):
        text='''       0        0 MASQUERADE all -- * !docker0 172.17.0.0/16 0.0.0.0/0
       4      264 MASQUERADE all -- * eth0 192.0.2.2 0.0.0.0/0'''
        self.assertEqual(MOD._counter_for(text,"MASQUERADE"),4)
    def test_initramfs_includes_ca(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            init=root/"init"; cand=root/"candidate"; ca=root/"ca"; out=root/"initrd"
            init.write_bytes(b"i"); cand.write_bytes(b"c"); ca.write_bytes(b"cert")
            MOD._build_initramfs(init,cand,ca,out)
            data=out.read_bytes()
            self.assertIn(b"etc/ssl/certs/ca-certificates.crt\0",data)
if __name__=="__main__": unittest.main()
