import importlib.util
import pathlib
import unittest

SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_d13_libsvctl_got.py"
SPEC=importlib.util.spec_from_file_location("d13",SCRIPT)
d13=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d13)

class D13Tests(unittest.TestCase):
    def test_got_load_and_jalr(self):
        self.assertEqual(d13.got_load("lw t9,-32720(gp)"),("t9",-32720))
        self.assertTrue(d13.is_jalr_t9("jalr t9"))

    def test_classify_pic_edges(self):
        funcs=[{"acceptedPicCallCount":1,"selectedGotLoadCount":1}]
        self.assertEqual(d13.classify(funcs,1),"E2_D13_LIBSVCTL_PIC_CALL_EDGES_RECOVERED")

if __name__=="__main__":
    unittest.main()
