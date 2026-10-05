import importlib.util,pathlib,unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_d19e_read_branch_role.py"
SPEC=importlib.util.spec_from_file_location("d19e",SCRIPT); d19e=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(d19e)
class T(unittest.TestCase):
  def test_predicates(self):
    self.assertEqual(d19e.predicate_class("beq v0,zero,20"),"v0_eq_zero")
    self.assertEqual(d19e.predicate_class("bne zero,v0,20"),"v0_ne_zero")
    self.assertEqual(d19e.predicate_class("bgtz v0,20"),"v0_gt_zero")
  def test_classes(self):
    self.assertEqual(d19e.instruction_class("jalr t9"),"call")
    self.assertEqual(d19e.instruction_class("beq v0,zero,20"),"branch")
  def test_classify(self):
    self.assertEqual(d19e.classify({"branchRoleEarned":True}),"E2_D19E_SVCTL_READ_CALLER_BRANCH_ROLE_EARNED")
if __name__=="__main__": unittest.main()
