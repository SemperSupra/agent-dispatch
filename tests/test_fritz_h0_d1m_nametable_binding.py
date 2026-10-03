import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1m_nametable_binding.py"
SPEC = importlib.util.spec_from_file_location("d1m", SCRIPT)
d1m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1m)


class D1mTests(unittest.TestCase):
    def test_split_top_level(self):
        self.assertEqual(
            d1m.split_top_level('"a", fn(1,2), {"x","y"}'),
            ['"a"', 'fn(1,2)', '{"x","y"}'],
        )

    def test_designated_nametable_binding(self):
        text = r'''
struct entry {
  const char *name;
  const char *runtime_name_0;
  const char *runtime_name_1;
};
static struct entry nametable[] = {
  { .name = "rootfs", .runtime_name_0 = "filesystem", .runtime_name_1 = "filesystem2" },
  { .name = "kernel", .runtime_name_0 = "kernel", .runtime_name_1 = "kernel2" },
};
void f(const char *name) {
  for (i = 0; i < 2; i++) {
    if (strcmp(name, nametable[i].name) == 0) break;
  }
  new_name = linux_fs_start == 0 ? nametable[i].runtime_name_0 : nametable[i].runtime_name_1;
}
'''
        r = d1m.recover_table(text)
        self.assertTrue(r["tableFound"])
        self.assertEqual(r["type"]["fieldNames"], ["name", "runtime_name_0", "runtime_name_1"])
        self.assertEqual(r["rowCount"], 2)
        self.assertEqual(r["indexBinding"]["uniqueStringComparisonSelectionField"], "name")
        bindings = d1m.row_bindings(r)
        self.assertEqual(bindings[0]["rowKey"], "rootfs")
        self.assertEqual(bindings[0]["runtimeName0"], "filesystem")
        self.assertEqual(bindings[0]["runtimeName1"], "filesystem2")

    def test_positional_rows_use_field_order(self):
        text = r'''
struct entry {
  const char *name;
  const char *runtime_name_0;
  const char *runtime_name_1;
};
static struct entry nametable[] = {
  { "rootfs", "filesystem", "filesystem2" },
};
int f(const char *name) {
  if (strcmp(name, nametable[i].name) == 0) return 1;
  return 0;
}
'''
        r = d1m.recover_table(text)
        self.assertEqual(r["rowCount"], 1)
        self.assertEqual(r["rows"][0]["runtimeNames"]["runtime_name_0"], "filesystem")
        self.assertEqual(r["rows"][0]["runtimeNames"]["runtime_name_1"], "filesystem2")

    def test_initializer_allows_declaration_attribute(self):
        text = r'''
struct entry {
  const char *name;
  const char *runtime_name_0;
  const char *runtime_name_1;
};
static struct entry nametable[2] __attribute__((unused)) = {
  { "rootfs", "filesystem", "filesystem2" },
};
'''
        r = d1m.recover_table(text)
        self.assertTrue(r["tableFound"])
        self.assertEqual(r["rowCount"], 1)

    def test_downstream_nametable_use_is_not_an_initializer(self):
        text = r'''
struct mtd_entry {
  const char *urlader_name;
  const char *runtime_name_0;
  const char *runtime_name_1;
};
void f(void) {
  new_name = linux_fs_start == 0
    ? nametable[i].runtime_name_0
    : nametable[i].runtime_name_1;
  if (x) { y = 1; }
}
'''
        self.assertIsNone(d1m.locate_table_initializer(text))
        r = d1m.recover_table(text)
        self.assertFalse(r["tableFound"])
        self.assertEqual(r["rowCount"], 0)

    def test_without_unique_selection_field_no_bindings(self):
        text = r'''
struct entry { const char *name; const char *alias; const char *runtime_name_0; const char *runtime_name_1; };
static struct entry nametable[] = {
  { "rootfs", "fs", "filesystem", "filesystem2" },
};
int f(const char *name) {
  strcmp(name, nametable[i].name);
  strcmp(name, nametable[i].alias);
  return 0;
}
'''
        r = d1m.recover_table(text)
        self.assertIsNone(r["indexBinding"]["uniqueStringComparisonSelectionField"])
        self.assertEqual(d1m.row_bindings(r), [])


if __name__ == "__main__":
    unittest.main()
