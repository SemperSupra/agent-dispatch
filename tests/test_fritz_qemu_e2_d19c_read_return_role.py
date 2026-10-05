import importlib.util, pathlib, unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_d19c_read_return_role.py"
SPEC=importlib.util.spec_from_file_location("d19c",SCRIPT); d19c=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(d19c)
class T(unittest.TestCase):
    def test_use_classes(self):
        self.assertTrue(d19c.reads_v0("beq v0,zero,20")); self.assertEqual(d19c.use_class("beq v0,zero,20"),"branch_condition")
        self.assertTrue(d19c.reads_v0("move a0,v0")); self.assertEqual(d19c.use_class("move a0,v0"),"argument_transfer")
        self.assertTrue(d19c.writes_v0("li v0,1")); self.assertFalse(d19c.writes_v0("sw v0,0(sp)"))
    def test_classify(self):
        self.assertEqual(d19c.classify({"roleEarned":True}),"E2_D19C_SVCTL_READ_RETURN_USE_ROLE_EARNED")
        self.assertEqual(d19c.classify({"roleEarned":False,"acceptedCallsiteCount":1}),"E2_D19C_SVCTL_READ_RETURN_USE_PARTIAL")
if __name__=="__main__": unittest.main()
