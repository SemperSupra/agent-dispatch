import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "sealed-public-execution.yml"


class SealedPublicSidecarCorrelationTests(unittest.TestCase):
    def test_sidecar_correlation_inputs_are_declared(self):
        source = WORKFLOW.read_text()
        self.assertIn("workset_id:", source)
        self.assertIn("delegation_id:", source)
        self.assertIn("assignment_id:", source)

    def test_run_name_is_exact_sidecar_prefix(self):
        source = WORKFLOW.read_text()
        self.assertIn(
            "run-name: sidecar:${{ inputs.workset_id }}:${{ inputs.delegation_id }}:${{ inputs.assignment_id }}",
            source,
        )

    def test_existing_bounded_capsule_contract_is_preserved(self):
        source = WORKFLOW.read_text()
        for name in ("capsule_b64:", "capsule_sha256:", "recipient:", "timeout_seconds:"):
            self.assertIn(name, source)

    def test_no_generic_execution_selector_was_added(self):
        source = WORKFLOW.read_text()
        forbidden = (
            "command:",
            "script_path:",
            "repository:",
            "repo:",
            "git_ref:",
            "checkout_ref:",
        )
        for value in forbidden:
            self.assertNotIn(value, source)


if __name__ == "__main__":
    unittest.main()
