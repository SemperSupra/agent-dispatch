"""RE-BENCH-P0: fixed public synthetic test of claim integrity and projections."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts" / "reversing_benchmark_p0.py"
SPEC = importlib.util.spec_from_file_location("benchmark_p0", PATH)
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)

def mock_profile(name, seed, artifact):
    starts = [(4096, 4120), (4128, 4154), (4160, 4168), (4200, 4207)]
    statuses = []
    for n in (1,4,8,12,0,-1):
        arr = []
        for i, (start, _end) in enumerate(starts):
            status = ("ENTRY_PC_OBSERVED_AND_RDI_ATTESTED" if i == 0 else
                      ("BREAKPOINT_OBSERVED_AFTER_RDI_INTERVENTION" if
                       (i==3 and n<=0 or i==1 and n>1 or i==2 and n>1) else
                       "NOT_OBSERVED_IN_THIS_INTERVENED_RUN"))
            arr.append({"interval_index":i,"target_delta_from_entry":start-4096,"status":status})
        statuses.append({
            "argument_n": n,"interval_count":4,"statuses":arr,
            "observed_indices":[x["interval_index"] for x in arr
                 if x["status"] != "NOT_OBSERVED_IN_THIS_INTERVENED_RUN"],
            "not_observed_indices":[x["interval_index"] for x in arr
                 if x["status"] == "NOT_OBSERVED_IN_THIS_INTERVENED_RUN"]
        })
    return {
        "profile": name, "branch_seed":seed,
        "symbol_table_absent":True,"unwind_tables_absent":True,
        "native_unmodified_fixture_exercised":True,
        "stripped_sha256":artifact,"original_sha256":"b"*64,
        "rdi_binary_unchanged_sha256":artifact,
        "stripped_original_text_sha256":"c"*64,
        "oracle_symbol_rva":4096,
        "independent_code_intervals":[{"start_rva":a,"end_exclusive_rva":b}
                                      for a,b in starts],
        "independent_objdump_boundary_oracle":{
            "classification":"EXACT_OBJDUMP_NONNOP_INTERVALS",
            "ghidra_interval_count":4,"objdump_nonnop_interval_count":4,
            "missing_nonnop_bytes":0,"extra_nonoracle_bytes":0},
        "independent_signed_branch_oracle":{
            "status":"SIGNED_JLE_DIRECT_EDGE_TO_ISLAND_3",
            "interval_index":3,"width_bits":64,
            "predicate":"signed_flags_le_zero_at_jle","target_rva":104},
        "native_second_replay":{
            "schema":"reversing-native-second-replay/v1",
            "scope":"PUBLIC_FIXED_NO_STDOUT_SYNTHETIC_ONLY",
            "independence":"FRESH_GDB_PROCESSES_SAME_HOST_SAME_INSTRUMENTATION",
            "artifact_sha256":artifact,
            "entry_rva":4096,"target_rva":4200,
            "cases":[
                {"input_n":0,"target_rva":4200,"verdict":"NATIVE_PC_WITNESS"},
                {"input_n":1,"target_rva":4200,"verdict":"NOT_OBSERVED_SAMPLE"}
            ]},
        "rdi_intervention":{
            "status":"RDI_INTERVENTION_ISLAND_SAMPLES_MEASURED",
            "baseline_argument_n":7,"abi":"X86_64_SYSV_FIRST_ARGUMENT_RDI",
            "arguments":statuses}
    }

def matrix():
    return {"schema":"reversing-stripped-contrast/v1",
            "result":"MATRIX_MEASURED_NOT_FULL_RECOVERY_PROOF",
            "profiles":[{"profile":"O0-no-unwind"},
                        mock_profile("O2-no-unwind",3,"a"*64),
                        mock_profile("O2-seed2-no-unwind",2,"d"*64)]}

class PublicSyntheticBenchmarkTests(unittest.TestCase):
    def test_four_deterministic_cases_and_cross_audience_consistency(self):
        x=B.reduce_matrix(matrix())
        self.assertEqual(x["overall"],"P0_FOUR_CONTROLS_CONSISTENT_NOT_SEALED_BLIND")
        self.assertEqual(len(x["cases"]),4)
        self.assertEqual([c["verdict"] for c in x["cases"]],
                         ["NATIVE_PC_WITNESS","NOT_OBSERVED_SAMPLE"]*2)
        self.assertEqual(x,B.reduce_matrix(matrix()))
        md=B.render_markdown(x)
        for case in x["cases"]:
            self.assertIn(case["claim_id"],md)
            self.assertIn(case["verdict"],md)
        self.assertIn(x["source_receipt_sha256"],md)
        self.assertIn("No-hit is not unreachability",md)
        self.assertIn("GENERATED_PUBLIC_SYNTHETIC_POSSIBLY_TRAINING_EXPOSED",md)

    def test_refuse_missing_native_hit_and_false_reachability(self):
        a=matrix()
        p=a["profiles"][1]
        row=next(x for x in p["rdi_intervention"]["arguments"] if x["argument_n"]==0)
        row["statuses"][3]["status"]="NOT_OBSERVED_IN_THIS_INTERVENED_RUN"
        row["observed_indices"].remove(3)
        row["not_observed_indices"].append(3)
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_refuse_forged_aggregate_status(self):
        a=matrix()
        row=next(x for x in a["profiles"][1]["rdi_intervention"]["arguments"]
                 if x["argument_n"]==0)
        row["not_observed_indices"]=[3]
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_refuse_shifted_target_pc_even_if_report_says_hit(self):
        a=matrix()
        row=next(x for x in a["profiles"][1]["rdi_intervention"]["arguments"]
                 if x["argument_n"]==0)
        row["statuses"][3]["target_delta_from_entry"]+=1
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_refuse_branch_target_disagreement(self):
        a=matrix()
        a["profiles"][1]["independent_signed_branch_oracle"]["target_rva"]=105
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_refuse_swapped_or_zero_or_mutated_binary_digest(self):
        for variant in ("swapped","zero","malformed"):
            with self.subTest(variant=variant):
                a=matrix()
                p=a["profiles"][1]
                if variant=="swapped":
                    p["rdi_binary_unchanged_sha256"]="e"*64
                elif variant=="zero":
                    p["stripped_sha256"]="0"*64
                    p["rdi_binary_unchanged_sha256"]="0"*64
                else:
                    p["stripped_sha256"]="x"
                with self.assertRaises(B.BenchmarkError):
                    B.reduce_matrix(a)

    def test_refuse_duplicate_or_unknown_input(self):
        for mutation in ("duplicate_profile","duplicate_arg","wrong_arg"):
            with self.subTest(mutation=mutation):
                a=matrix()
                if mutation=="duplicate_profile":
                    a["profiles"][2]["profile"]="O2-no-unwind"
                elif mutation=="duplicate_arg":
                    a["profiles"][1]["rdi_intervention"]["arguments"][1]["argument_n"]=1
                else:
                    a["profiles"][1]["rdi_intervention"]["arguments"][0]["argument_n"]=99
                with self.assertRaises(B.BenchmarkError):
                    B.reduce_matrix(a)

    def test_refuse_replay_artifact_mismatch(self):
        a=matrix()
        a["profiles"][1]["native_second_replay"]["artifact_sha256"]="f"*64
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_refuse_replay_target_rva_shift(self):
        a=matrix()
        a["profiles"][1]["native_second_replay"]["cases"][0]["target_rva"]=4201
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_refuse_replay_stale_witness(self):
        a=matrix()
        a["profiles"][1]["native_second_replay"]["cases"][0]["verdict"]="NOT_OBSERVED_SAMPLE"
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_refuse_second_replay_missing_or_duplicate(self):
        for case in ("missing","duplicate"):
            with self.subTest(case=case):
                a=matrix()
                rs=a["profiles"][1]["native_second_replay"]["cases"]
                if case=="missing":
                    rs.pop()
                else:
                    rs[1]["input_n"]=0
                with self.assertRaises(B.BenchmarkError):
                    B.reduce_matrix(a)

    def test_refuse_legacy_matrix_without_independent_intervals(self):
        a=matrix()
        del a["profiles"][1]["independent_code_intervals"]
        with self.assertRaises(B.BenchmarkError):
            B.reduce_matrix(a)

    def test_no_unknown_relabel_or_platform_claim(self):
        x=B.reduce_matrix(matrix())
        self.assertTrue(all(c["scope"]=="ONE_STRIPPED_ELF_NATIVE_GDB_PC_SAMPLE"
                            for c in x["cases"]))
        self.assertNotIn("UNREACHABLE",json.dumps(x))
        self.assertNotIn("SEALED_BLIND",x["exposure_class"])

if __name__ == "__main__":
    unittest.main()
