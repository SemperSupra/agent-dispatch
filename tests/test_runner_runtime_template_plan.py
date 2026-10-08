from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod

CONTRACT=load_module("runner_runtime_template_contract",ROOT/"scripts"/"runner_runtime_template_contract.py")
PLAN=load_module("runner_runtime_template_plan",ROOT/"scripts"/"runner_runtime_template_plan.py")
CATALOG=ROOT/"config"/"runner-runtime-templates.json"


class RunnerRuntimeTemplatePlanTests(unittest.TestCase):
    def setUp(self):
        self.catalog=CONTRACT.load(CATALOG)

    def test_full_truenas_ubuntu_plan_replays_all_public_predicates(self):
        plan=PLAN.build_plan(self.catalog,"truenas-ubuntu-24.04-x64")
        predicates={x["predicate"] for x in plan["steps"]}
        self.assertIn("primitive:docker-container-bind",predicates)
        self.assertIn("primitive:kvm-vcpu-sudo",predicates)
        self.assertIn("workload:agent-dispatch-contract-native",predicates)
        self.assertIn("workload:agent-dispatch-contract-docker",predicates)
        self.assertIn("workload:android-api35-emulator-setup-boot",predicates)
        self.assertEqual(plan["external_oracles_required"],[])
        self.assertEqual(plan["runner_agent_version"],"2.337.0")
        self.assertFalse(plan["t7_enhancement_required"])
        self.assertFalse(plan["t8_placement_admission"])

    def test_system_container_derives_from_slim_and_remains_enhancement(self):
        plan=PLAN.build_plan(self.catalog,"truenas-system-container-x64")
        self.assertEqual(plan["compatible_base"],"truenas-ubuntu-slim-x64")
        self.assertEqual(plan["gha_reference"],"ubuntu-slim")
        self.assertTrue(plan["t7_enhancement_required"])
        self.assertIn(
            "workload:agent-dispatch-contract-native",
            {x["predicate"] for x in plan["steps"]},
        )

    def test_windows_predicates_remain_external_until_portable_oracle_exists(self):
        plan=PLAN.build_plan(self.catalog,"windows-dev-windows-2025-x64")
        self.assertGreaterEqual(len(plan["external_oracles_required"]),5)
        self.assertTrue(all(x.startswith("primitive:") for x in plan["external_oracles_required"]))
        self.assertFalse(plan["t8_placement_admission"])

    def test_portable_agent_contract_preserves_workload_sandbox(self):
        text=(ROOT/"scripts"/"runner_runtime_agent_contract.py").read_text(encoding="utf-8")
        self.assertIn('"--network","none"',text)
        self.assertIn('"--read-only"',text)
        self.assertIn("type=bind,src=",text)
        self.assertIn("dst=/src,readonly",text)
        self.assertIn("tests/test_sealed_public_execution.py",text)

    def test_unknown_candidate_fails_closed(self):
        with self.assertRaises(PLAN.PlanError):
            PLAN.build_plan(self.catalog,"ubuntu-latest-local")


if __name__=="__main__":
    unittest.main()
