import importlib.util
import pathlib
import unittest

SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_d12_libsvctl_functions.py"
SPEC=importlib.util.spec_from_file_location("d12",SCRIPT)
d12=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d12)

class D12Tests(unittest.TestCase):
    def test_asm_line(self):
        self.assertEqual(d12.asm_line("  1000: 24020008  li v0,8"),"li v0,8")

    def test_symbol_set_is_bounded(self):
        self.assertEqual(set(d12.FUNCTIONS),{
            "_svctl_init","_svctl_connect","_svctl_send_pkt","_svctl_send","_svctl_read"
        })

if __name__=="__main__":
    unittest.main()
