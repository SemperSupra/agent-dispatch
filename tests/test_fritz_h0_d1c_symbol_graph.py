import importlib.util
import pathlib
import unittest

SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_h0_d1c_symbol_graph.py"
SPEC=importlib.util.spec_from_file_location("d1c",SCRIPT)
d1c=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1c)


class D1cTests(unittest.TestCase):
    def test_function_seed_and_calls(self):
        text=r"""
static int choose_slot(void) {
    int linux_fs_start = 1;
    return tffs_read(linux_fs_start) + avm_mtd_select();
}
"""
        fs=d1c.functions(text)
        self.assertEqual(len(fs),1)
        self.assertEqual(fs[0]["name"],"choose_slot")
        self.assertIn("linux_fs_start",fs[0]["seedTokens"])
        self.assertIn("tffs_read",fs[0]["calls"])
        self.assertIn("avm_mtd_select",fs[0]["calls"])

    def test_macro_reduction_has_no_value(self):
        r=d1c.reduce_file("x.h","#define linux_fs_start 42\n")
        self.assertEqual(r["macros"][0]["name"],"linux_fs_start")
        self.assertNotIn("value",r["macros"][0])

    def test_graph_links_defined_callee(self):
        reduced={
            "a.c":{"functions":[{"name":"a","calls":["tffs_read"],"seedTokens":["linux_fs_start"]}]},
            "b.c":{"functions":[{"name":"tffs_read","calls":[],"seedTokens":["tffs"]}]},
        }
        g=d1c.graph(reduced)
        edge=g["callEdges"][0]
        self.assertEqual(edge["callee"],"tffs_read")
        self.assertEqual(edge["calleeFiles"],["b.c"])


if __name__=="__main__":
    unittest.main()
