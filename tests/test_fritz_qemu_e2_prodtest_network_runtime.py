import argparse
import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "fritz_qemu_e2_prodtest_network_runtime.py"
spec = importlib.util.spec_from_file_location("fritz_e2_r5", SCRIPT)
r5 = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(r5)


class ProdtestNetworkRuntimeTests(unittest.TestCase):
    def test_shared_harness_default_is_backward_compatible(self):
        args = r5.r4.r3.parse_args([])
        self.assertEqual(args.supervisor_target, "ctlmgr.service")

    def test_fixed_trace_accepts_selected_target(self):
        raw = '101 openat(AT_FDCWD,"/lib/systemd/system/prodtest-network.target",O_RDONLY) = 3\n'
        e = r5.r4.r3.fixed_trace_evidence(
            raw,
            {"selected_target": "/lib/systemd/system/prodtest-network.target"},
        )
        self.assertEqual(e["paths"]["selected_target"]["hitCount"], 1)
        self.assertEqual(e["paths"]["selected_target"]["successCount"], 1)

    def test_annotate_requires_exact_target(self):
        receipt = {
            "runtime": {
                "supervisorArguments": [
                    "/lib/systemd/system",
                    "prodtest-network.target",
                ]
            },
            "safety": {},
        }
        out = r5.annotate(receipt)
        self.assertEqual(out["targetSelection"]["admittedUnitCount"], 6)
        self.assertTrue(out["targetSelection"]["ctlmgrAdmitted"])
        self.assertFalse(out["targetSelection"]["broaderNetworkTargetUsed"])

    def test_annotate_rejects_other_target(self):
        with self.assertRaises(RuntimeError):
            r5.annotate({
                "runtime": {
                    "supervisorArguments": [
                        "/lib/systemd/system",
                        "network.target",
                    ]
                },
                "safety": {},
            })


if __name__ == "__main__":
    unittest.main()
