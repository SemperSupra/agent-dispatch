import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1n_runtime_name_expressions.py"
SPEC = importlib.util.spec_from_file_location("d1n", SCRIPT)
d1n = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1n)


class D1nTests(unittest.TestCase):
    def test_positional_macro_identifiers_resolve(self):
        text = r'''
#define ROOT_A "filesystem"
#define ROOT_B "filesystem2"
struct mtd_entry {
  const char *urlader_name;
  const char *runtime_name_0;
  const char *runtime_name_1;
};
static struct mtd_entry nametable[] = {
  { "rootfs", ROOT_A, ROOT_B },
};
'''
        r = d1n.reduce_rows(text)
        self.assertTrue(r["tableFound"])
        self.assertEqual(r["rowCount"], 1)
        row = r["rows"][0]["fields"]
        self.assertEqual(
            row["runtime_name_0"]["resolution"]["resolvedDestination"],
            "filesystem",
        )
        self.assertEqual(
            row["runtime_name_1"]["resolution"]["resolvedDestination"],
            "filesystem2",
        )

    def test_designated_unique_safe_literal_in_call_resolves(self):
        text = r'''
struct mtd_entry {
  const char *urlader_name;
  const char *runtime_name_0;
  const char *runtime_name_1;
};
static struct mtd_entry nametable[] = {
  {
    .urlader_name = "rootfs",
    .runtime_name_0 = WRAP("filesystem"),
    .runtime_name_1 = WRAP("filesystem2")
  },
};
'''
        r = d1n.reduce_rows(text)
        row = r["rows"][0]["fields"]
        self.assertEqual(
            row["runtime_name_0"]["resolution"]["resolution"],
            "unique_safe_literal_in_expression",
        )
        self.assertIn(
            "function_like",
            row["runtime_name_0"]["skeleton"]["identifiers"][0]["roles"],
        )

    def test_ambiguous_identifier_definition_stays_partial(self):
        text = r'''
#define ROOT_A "filesystem"
#define ROOT_A "filesystem2"
struct mtd_entry {
  const char *urlader_name;
  const char *runtime_name_0;
  const char *runtime_name_1;
};
static struct mtd_entry nametable[] = {
  { "rootfs", ROOT_A, ROOT_A },
};
'''
        r = d1n.reduce_rows(text)
        res = r["rows"][0]["fields"]["runtime_name_0"]["resolution"]
        self.assertIsNone(res["resolvedDestination"])
        self.assertEqual(res["resolution"], "identifier_definition_ambiguous")
        self.assertEqual(res["definitionCount"], 2)

    def test_skeleton_does_not_publish_non_safe_literal(self):
        s = d1n.expression_skeleton('FN("not a destination/value")')
        self.assertEqual(s["safeLiteralCandidates"], [])
        self.assertIsNone(s["directSafeDestination"])
        self.assertEqual(s["identifiers"][0]["name"], "FN")

    def test_resolved_destination_projection(self):
        reduced = {
            "rows": [{
                "fields": {
                    "runtime_name_0": {"resolution": {"resolvedDestination": "filesystem"}},
                    "runtime_name_1": {"resolution": {"resolvedDestination": "filesystem2"}},
                }
            }]
        }
        self.assertEqual(
            d1n.resolved_destinations(reduced),
            [
                {"rowIndex": 0, "field": "runtime_name_0", "destination": "filesystem"},
                {"rowIndex": 0, "field": "runtime_name_1", "destination": "filesystem2"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
