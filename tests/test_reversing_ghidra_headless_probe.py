import copy
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "reversing_ghidra_headless_probe.py"
SPEC = importlib.util.spec_from_file_location("reversing_ghidra_headless_probe", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

def original():
    return {
        "schema": "ghidra-function-ranges/v1", "image_base": "4194304",
        "executable_format": "Executable and Linking Format (ELF)",
        "functions": [{"name": "fixture_target", "entry": "4198690",
                       "ranges": [{"start": "4198690", "end_exclusive": "4198710"}]}]
    }

class GhidraExportParserTests(unittest.TestCase):
    def test_exact_static_range_parsed(self):
        x = MOD.parse_export(original(), 4198690, 32, 4194304)
        self.assertEqual(x, {"id": "ghidra_target", "rva": 4386, "size": 20})

    def test_reject_symbol_divergence(self):
        x = original()
        x["functions"][0]["entry"] = "4198691"
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

    def test_reject_non_elf(self):
        x = original()
        x["executable_format"] = "Portable Executable"
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

    def test_reject_duplicate_target(self):
        x = original()
        x["functions"].append(copy.deepcopy(x["functions"][0]))
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

    def test_reject_range_over_expansion(self):
        x = original()
        x["functions"][0]["ranges"][0]["end_exclusive"] = str(4198690 + 33)
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

    def test_reject_range_gap(self):
        x = original()
        x["functions"][0]["ranges"].append({"start": "4198720", "end_exclusive": "4198724"})
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

    def test_reject_range_not_containing_entry(self):
        x = original()
        x["functions"][0]["ranges"][0]["start"] = "4198691"
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

    def test_reject_wrong_schema(self):
        x = original()
        x["schema"] = "unknown"
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

    def test_reject_raw_binary_field(self):
        x = original()
        x["raw_binary"] = "private"
        with self.assertRaises(MOD.GhidraOracleError):
            MOD.parse_export(x, 4198690, 32, 4194304)

if __name__ == "__main__":
    unittest.main()
