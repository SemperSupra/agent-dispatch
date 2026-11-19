#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from truenas_session_state import CapsuleOutcome, decide_after_capsule, finalize_session

def outcome(**overrides):
    base=dict(
        capsule_id="capsule-001",
        verdict="SUPPORTED",
        mutating=True,
        cleanup_required=True,
        cleanup_satisfied=True,
        platform_healthy=True,
        authority_satisfied=True,
        resource_guardrail_satisfied=True,
    )
    base.update(overrides)
    return CapsuleOutcome(**base)

class SessionStateTests(unittest.TestCase):
    def test_supported_clean_capsule_allows_next(self):
        d=decide_after_capsule(outcome())
        self.assertTrue(d.continue_mutation)
        self.assertEqual(d.session_classification,"IN_PROGRESS")

    def test_product_oracle_failure_with_clean_membrane_allows_independent_next(self):
        d=decide_after_capsule(outcome(verdict="ORACLE_FAILURE"))
        self.assertTrue(d.continue_mutation)
        self.assertEqual(d.next_state,"READY")
        self.assertEqual(finalize_session([outcome(verdict="ORACLE_FAILURE")]),"SESSION_CLEAN")

    def test_cleanup_failure_contaminates_and_stops(self):
        d=decide_after_capsule(outcome(verdict="ORACLE_FAILURE",cleanup_satisfied=False))
        self.assertFalse(d.continue_mutation)
        self.assertEqual(d.session_classification,"SESSION_CONTAMINATED")

    def test_platform_health_failure_stops(self):
        d=decide_after_capsule(outcome(platform_healthy=False))
        self.assertFalse(d.continue_mutation)
        self.assertEqual(d.session_classification,"PLATFORM_UNHEALTHY")

    def test_authority_drift_stops_before_later_mutation(self):
        d=decide_after_capsule(outcome(authority_satisfied=False))
        self.assertFalse(d.continue_mutation)
        self.assertEqual(d.session_classification,"AUTHORITY_MISMATCH")

    def test_resource_guardrail_stops(self):
        d=decide_after_capsule(outcome(resource_guardrail_satisfied=False))
        self.assertFalse(d.continue_mutation)
        self.assertEqual(d.session_classification,"RESOURCE_GUARDRAIL")

    def test_read_only_failure_does_not_require_cleanup_if_platform_is_healthy(self):
        d=decide_after_capsule(outcome(
            verdict="ORACLE_FAILURE",mutating=False,cleanup_required=False,cleanup_satisfied=False
        ))
        self.assertTrue(d.continue_mutation)

    def test_unknown_verdict_fails_closed(self):
        d=decide_after_capsule(outcome(verdict="MAGIC_PASS"))
        self.assertFalse(d.continue_mutation)
        self.assertEqual(d.session_classification,"HARNESS_FAILURE")

    def test_session_clean_does_not_mean_all_capsules_supported(self):
        rows=[outcome(),outcome(capsule_id="capsule-002",verdict="DOCUMENTED_NEGATIVE")]
        self.assertEqual(finalize_session(rows),"SESSION_CLEAN")
        self.assertEqual(rows[1].verdict,"DOCUMENTED_NEGATIVE")

if __name__=="__main__":
    unittest.main()
