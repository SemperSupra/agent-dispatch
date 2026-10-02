import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1e_selector_tables.py"
SPEC = importlib.util.spec_from_file_location("d1e", SCRIPT)
d1e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1e)


class D1eTests(unittest.TestCase):
    def test_pointer_array_owner_resolution(self):
        text = r'''
static const char * const env_names[] = {
  "linux_fs_start",
};
'''
        r = d1e.reduce_file("x.c", text)
        self.assertEqual(len(r), 1)
        self.assertTrue(r[0]["ownerResolved"])
        self.assertEqual(r[0]["owner"]["owner"], "env_names")

    def test_typed_negative_does_not_overclaim_recovery(self):
        schema = {"owners": [], "derived": {"occurrenceCount": 1, "resolvedOwnerCount": 0}}
        classification, oracle = d1e.classify_schema(schema, [])
        self.assertTrue(oracle)
        self.assertEqual(classification, "H0_D1E_NO_TABLE_OWNER_RECOVERED")

    def test_global_table_owner_and_fields(self):
        text = r'''
struct entry {
  const char *name;
  int id;
  int (*reader)(void);
};
static const struct entry env_table[] = {
  { .name = "linux_fs_start", .id = TFFS_ID_LINUX_FS_START, .reader = avm_urlader_getenv },
};
'''
        r = d1e.reduce_file("x.c", text)
        self.assertEqual(len(r), 1)
        self.assertTrue(r[0]["ownerResolved"])
        self.assertEqual(r[0]["owner"]["owner"], "env_table")
        self.assertIn("name", r[0]["entrySchema"]["designatedFields"])
        self.assertIn("TFFS_ID_LINUX_FS_START", r[0]["entrySchema"]["enumLikeReferences"])
        self.assertIn("avm_urlader_getenv", r[0]["entrySchema"]["callbackLikeReferences"])

    def test_no_numeric_or_string_values_in_schema(self):
        text = 'static const struct e t[] = {{ .name="linux_fs_start", .id=42, .cb=read_env }};'
        r = d1e.reduce_file("x.c", text)[0]["entrySchema"]
        serialized = str(r)
        self.assertNotIn("42", serialized)
        self.assertNotIn('"linux_fs_start"', serialized)


if __name__ == "__main__":
    unittest.main()
