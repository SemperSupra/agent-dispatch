import copy
import importlib.util
from pathlib import Path
import unittest

S = Path(__file__).resolve().parents[1] / "scripts" / "reversing_ghidra_stripped_probe.py"
SPEC = importlib.util.spec_from_file_location("stripped_reversing", S)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

def fixture():
    return {"schema": "ghidra-function-ranges/v1", "image_base": "4194304",
            "executable_format": "Executable and Linking Format (ELF)",
            "functions": [{"name": "FUN_00401122", "entry": "4198690",
                           "ranges": [{"start": "4198690", "end_exclusive": "4198710"}]}]}

class StrippedParserTests(unittest.TestCase):
    def test_accept_unknown_generated_name(self):
        self.assertEqual(M.parse_stripped_export(fixture(), 4198690, 32, 4194304),
                         {"id": "stripped_function_recovered", "rva": 4386, "size": 20})

    def test_reject_entry_missing(self):
        x=fixture(); x["functions"][0]["entry"]="4198692"
        with self.assertRaises(M.StrippedOracleError):
            M.parse_stripped_export(x,4198690,32,4194304)

    def test_reject_duplicate_entry(self):
        x=fixture(); x["functions"].append(copy.deepcopy(x["functions"][0]))
        with self.assertRaises(M.StrippedOracleError):
            M.parse_stripped_export(x,4198690,32,4194304)

    def test_reject_widened_guess(self):
        x=fixture(); x["functions"][0]["ranges"][0]["end_exclusive"]="4198790"
        with self.assertRaises(M.StrippedOracleError):
            M.parse_stripped_export(x,4198690,32,4194304)

    def test_reject_structural_gap(self):
        x=fixture(); x["functions"][0]["ranges"].append({"start":"4198720","end_exclusive":"4198721"})
        with self.assertRaises(M.StrippedOracleError):
            M.parse_stripped_export(x,4198690,32,4194304)

    def test_reject_raw_memory_data(self):
        x=fixture(); x["raw_memory"]="untrusted"
        with self.assertRaises(M.StrippedOracleError):
            M.parse_stripped_export(x,4198690,32,4194304)

if __name__ == "__main__":
    unittest.main()
