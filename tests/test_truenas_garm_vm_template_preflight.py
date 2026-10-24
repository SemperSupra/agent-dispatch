import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import truenas_garm_vm_template_preflight as pre
from test_truenas_garm_vm_pre_b4 import PRODUCER, fixture

def snapshot():
    return {
        "schema": pre.SNAPSHOT_SCHEMA,
        "version": pre.TARGET,
        "available_methods": sorted(pre.REQUIRED_METHODS),
        "template_rows": [{"name": pre.validate_fixture(fixture(), PRODUCER)["template_runtime_name"], "id": 42}],
        "template_state": "STOPPED",
        "template_devices": [
            {"dtype": "DISK", "zvol_backed": True, "raw_backed": False},
            {"dtype": "NIC", "zvol_backed": False, "raw_backed": False},
        ],
        "read_methods_used": ["system.version", "core.get_methods", "vm.query",
                              "vm.status", "vm.device.query"],
    }

class VMReadOnlyPreflightTests(unittest.TestCase):
    def test_suitable_observation_does_not_prove_source_or_support(self):
        result = pre.evaluate(fixture(), PRODUCER, snapshot())
        self.assertEqual(result["classification"], "TEMPLATE_OBSERVED_SOURCE_UNVERIFIED")
        self.assertTrue(result["oracleSatisfied"])
        for key in ("runtime_mutation_performed", "runtime_support_admitted",
                    "template_source_provenance_verified", "guest_boot_observed",
                    "zero_residue_runtime_proven"):
            self.assertFalse(result[key])

    def test_observer_uses_only_reads_and_redacts_opaque_fields(self):
        name = pre.validate_fixture(fixture(), PRODUCER)["template_runtime_name"]
        calls = []
        def rpc(method, params):
            calls.append(method)
            if method == "system.version": return pre.TARGET
            if method == "core.get_methods": return {m: {} for m in pre.REQUIRED_METHODS}
            if method == "vm.query": return [{"name": name, "id": 42, "opaque": "not-for-receipt"}]
            if method == "vm.status": return {"state": "STOPPED"}
            if method == "vm.device.query":
                return [{"attributes": {"dtype": "DISK", "path": "/dev/zvol/rdtepool/base", "opaque": "not-for-receipt"}}]
            raise AssertionError(method)
        result = pre.collect_snapshot(rpc, name)
        self.assertEqual(calls, ["system.version", "core.get_methods", "vm.query",
                                 "vm.status", "vm.device.query"])
        self.assertNotIn("not-for-receipt", str(result))
        self.assertNotIn("/dev/zvol/rdtepool/base", str(result))
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, result)["classification"],
                         "TEMPLATE_OBSERVED_SOURCE_UNVERIFIED")

    def test_absent_wrong_version_or_methods_fail_closed(self):
        s = snapshot()
        s["template_rows"] = []
        s["read_methods_used"] = s["read_methods_used"][:3]
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "TEMPLATE_MISSING")
        s = snapshot()
        s["version"] = "TrueNAS-25.10.7"
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "EXACT_TARGET_MISMATCH")
        s = snapshot()
        s["available_methods"].remove("vm.clone")
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "VM_METHODS_ABSENT")

    def test_state_disk_shape_and_ownership(self):
        s = snapshot()
        s["template_state"] = "RUNNING"
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "TEMPLATE_NOT_STOPPED")
        s = snapshot()
        s["template_devices"][0] = {"dtype": "RAW", "raw_backed": True}
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "RAW_DISK_NOT_CLONEABLE")
        s = snapshot()
        s["template_devices"][0]["zvol_backed"] = False
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "ZVOL_BOOT_DISK_NOT_EXACT")
        s = snapshot()
        s["template_rows"][0]["name"] = "foreign_vm"
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "TEMPLATE_NAME_DRIFT")
        s = snapshot()
        s["template_rows"].append(s["template_rows"][0].copy())
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "TEMPLATE_AMBIGUOUS")

    def test_untrusted_observer_and_unsubstantiated_provenance(self):
        s = snapshot()
        s["read_methods_used"].append("vm.start")
        self.assertEqual(pre.evaluate(fixture(), PRODUCER, s)["reason_code"], "UNTRUSTED_OBSERVER")
        s = snapshot()
        s["source_provenance_receipt"] = {"claimed": True}
        self.assertFalse(pre.evaluate(fixture(), PRODUCER, s)["template_source_provenance_verified"])

if __name__ == "__main__":
    unittest.main()
