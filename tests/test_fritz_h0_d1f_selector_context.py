import importlib.util
import pathlib
import unittest

SCRIPT=pathlib.Path(__file__).parents[1]/"scripts"/"fritz_h0_d1f_selector_context.py"
SPEC=importlib.util.spec_from_file_location("d1f",SCRIPT)
d1f=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d1f)

class D1fTests(unittest.TestCase):
    def test_string_initializer_context(self):
        text='static const char *names[] = { "linux_fs_start", "other" };'
        r=d1f.reduce({"x.c":text})
        o=r["occurrences"][0]
        self.assertEqual(o["lexicalState"],"string")
        self.assertEqual(o["contextClass"],"brace-contained-string")
        self.assertEqual(o["delimiterDepth"]["braceDepth"],1)
        self.assertIn("names",o["safeIdentifiers"])

    def test_comment_is_distinguished(self):
        text='/* linux_fs_start */\nint x;'
        o=d1f.reduce({"x.c":text})["occurrences"][0]
        self.assertEqual(o["lexicalState"],"comment")
        self.assertEqual(o["contextClass"],"comment")

    def test_preprocessor_string(self):
        text='#define KEY_NAME "linux_fs_start"\n'
        o=d1f.reduce({"x.h":text})["occurrences"][0]
        self.assertEqual(o["lexicalState"],"string")
        self.assertTrue(o["preprocessor"])
        self.assertEqual(o["directive"],"define")
        self.assertEqual(o["contextClass"],"preprocessor-string")

    def test_no_literal_value_leak(self):
        text='static const char *name = "linux_fs_start";'
        o=d1f.reduce({"x.c":text})["occurrences"][0]
        self.assertNotIn("linux_fs_start",str(o["safeIdentifiers"]))
        self.assertNotIn('"linux_fs_start"',str(o))

if __name__=="__main__":
    unittest.main()
