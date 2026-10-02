import importlib.util, pathlib, unittest
SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_qemu_e2_activation_semantics.py"
SPEC=importlib.util.spec_from_file_location("d7",SCRIPT)
d7=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d7)

class D7Tests(unittest.TestCase):
    def test_literal_target_start(self):
        inv=d7.svctl_invocations("/bin/svctl start prodtest-network.target\n","/x")
        self.assertEqual(inv[0]["verb"],"start")
        self.assertEqual(inv[0]["operandShape"][0],{"kind":"unit","value":"prodtest-network.target"})

    def test_variable_binding_correlation(self):
        text="target=prodtest-network.target\n/bin/svctl start $target\n"
        inv=d7.svctl_invocations(text,"/x")
        binds=d7.variable_unit_bindings(text,"/x")
        rel=d7.correlate(inv,binds)
        self.assertEqual(rel[0]["unit"],"prodtest-network.target")
        self.assertEqual(rel[0]["verb"],"start")

    def test_positional_is_not_resolved(self):
        inv=d7.svctl_invocations("/bin/svctl start $1\n","/x")
        self.assertEqual(inv[0]["operandShape"][0]["kind"],"variable")
        self.assertEqual(d7.correlate(inv,[]),[])

if __name__=="__main__":unittest.main()
