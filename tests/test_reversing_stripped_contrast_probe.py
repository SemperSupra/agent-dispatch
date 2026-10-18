import copy
import importlib.util
from pathlib import Path
import unittest

P = Path(__file__).resolve().parents[1] / "scripts/reversing_stripped_contrast_probe.py"
S = importlib.util.spec_from_file_location("reversing_contrast", P)
M = importlib.util.module_from_spec(S)
S.loader.exec_module(M)


def fixture():
    return {"schema": "ghidra-function-ranges/v1", "image_base": "4194304",
            "executable_format": "Executable and Linking Format (ELF)",
            "functions": [{"name": "FUN_00401122", "entry": "4198690",
                           "ranges": [{"start": "4198690", "end_exclusive": "4198722"}]}]}


class ContrastTests(unittest.TestCase):
    def check(self, raw, size=32):
        return M.function_assessment(raw, 4198690, size, 4194304)

    def test_exact_body(self):
        self.assertEqual(self.check(fixture())["outcome"], "EXACT_BODY")

    def test_partial_body_not_promoted(self):
        x = fixture()
        x["functions"][0]["ranges"][0]["end_exclusive"] = "4198712"
        result = self.check(x)
        self.assertEqual(result["outcome"], "PARTIAL_BODY")
        self.assertEqual(result["recovered_bytes"], 22)

    def test_oversized_body_not_promoted(self):
        self.assertEqual(self.check(fixture(), 20)["outcome"], "BODY_EXTENDS_BEYOND_ORACLE")

    def test_unknown_function_preserved(self):
        x = fixture(); x["functions"] = []
        self.assertEqual(self.check(x)["outcome"], "ENTRY_NOT_FOUND")

    def test_duplicate_entry_preserved(self):
        x = fixture(); x["functions"].append(copy.deepcopy(x["functions"][0]))
        self.assertEqual(self.check(x)["outcome"], "AMBIGUOUS_ENTRY")

    def test_discontiguous_body_not_promoted(self):
        x = fixture(); x["functions"][0]["ranges"].append({"start": "4198750", "end_exclusive": "4198760"})
        r = self.check(x)
        self.assertEqual(r["outcome"], "INVALID_FUNCTION_BODY")
        self.assertEqual(r["diagnostic"], "MULTIRANGE_OR_EMPTY_BODY")
        self.assertEqual(r["reported_range_count"], 2)

    def test_wrong_image_base_fail_closed(self):
        x = fixture(); x["image_base"] = "4194303"
        with self.assertRaises(M.MatrixError): self.check(x)

    def test_unexpected_private_field_fail_closed(self):
        x = fixture(); x["source"] = "restricted"
        with self.assertRaises(M.MatrixError): self.check(x)

    def test_unregistered_profile_not_executed(self):
        with self.assertRaises(M.MatrixError): M.observe(Path("/no-ghidra"), "user-supplied")

if __name__ == "__main__":
    unittest.main()
