import hashlib
import inspect
import unittest

import candidate


EXPECTED_FUNCTION_SHA256 = "ae26c04e43e6f98b247709d067a7656986a4bb1eb137ebd6e514295301fed4ca"


class ProjectionBindingTests(unittest.TestCase):
    def test_exact_function_text_is_bound_to_private_candidate(self):
        source = inspect.getsource(candidate._normalize_terminal_result)
        self.assertEqual(hashlib.sha256(source.encode("utf-8")).hexdigest(), EXPECTED_FUNCTION_SHA256)


class TrustSemanticsTests(unittest.TestCase):
    projection = {"contract_id": "contract-001"}
    assignment = {"assignment_id": "assignment-001"}

    def normalize(self, conclusion, *, html_url="https://example.invalid/run/42"):
        return candidate._normalize_terminal_result(
            self.projection,
            self.assignment,
            [{
                "id": 42,
                "status": "completed",
                "conclusion": conclusion,
                "html_url": html_url,
                "created_at": "2026-09-29T10:00:00Z",
                "updated_at": "2026-09-29T10:01:00Z",
            }],
        )

    def test_success_is_execution_only_not_validation(self):
        result = self.normalize("success")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["validator"], {"status": "not-run", "refs": []})
        self.assertEqual(result["evidence_refs"], ["https://example.invalid/run/42"])
        self.assertIn("not independent validation or acceptance", result["notes"])

    def test_failure_is_execution_only_not_validator_failure(self):
        result = self.normalize("failure")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["validator"], {"status": "not-run", "refs": []})
        self.assertEqual(result["evidence_refs"], ["https://example.invalid/run/42"])

    def test_provider_evidence_is_optional_but_never_validator_evidence(self):
        result = self.normalize("success", html_url="")
        self.assertEqual(result["evidence_refs"], [])
        self.assertEqual(result["validator"]["refs"], [])

    def test_nonterminal_run_does_not_create_result_or_acceptance(self):
        result = candidate._normalize_terminal_result(
            self.projection,
            self.assignment,
            [{"id": 42, "status": "in_progress", "conclusion": None}],
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
