import unittest
from rules import assess, Hold

def rule(t):
    return {"type":t,"ruleset_source_type":"Repository"}

class BranchRulesCensus(unittest.TestCase):
    def test_both_rules_visible_is_still_not_external_witness(self):
        x=assess([rule("deletion"),rule("non_fast_forward"),rule("pull_request")])
        self.assertEqual(x["policy_evidence"],"BOTH_RULE_TYPES_VISIBLE")
        self.assertEqual(x["protected_external_high_water"],"NOT_TESTED")
        self.assertEqual(x["actual_non_fast_forward_denial"],"NOT_TESTED")
    def test_missing_force_rule_holds(self):
        self.assertEqual(assess([rule("deletion")])["policy_evidence"],"HOLD_RULES_NOT_SUFFICIENT")
    def test_missing_deletion_rule_holds(self):
        self.assertEqual(assess([rule("non_fast_forward")])["policy_evidence"],"HOLD_RULES_NOT_SUFFICIENT")
    def test_empty_rules_hold(self):
        x=assess([])
        self.assertEqual(x["policy_evidence"],"HOLD_RULES_NOT_SUFFICIENT")
    def test_extra_unrelated_rule_never_upgrades(self):
        x=assess([rule("required_status_checks")])
        self.assertEqual(x["policy_evidence"],"HOLD_RULES_NOT_SUFFICIENT")
    def test_nonlist_denied(self):
        with self.assertRaisesRegex(Hold,"INVALID"):assess({"message":"error"})
    def test_unknown_rule_is_not_unsafe_guess(self):
        x=assess([rule("future_protection")])
        self.assertEqual(x["policy_evidence"],"HOLD_RULES_NOT_SUFFICIENT")
    def test_malformed_rule_denied(self):
        with self.assertRaisesRegex(Hold,"OBJECT"):assess([{"unknown":"value"}])
    def test_unbounded_response_denied(self):
        with self.assertRaisesRegex(Hold,"TRUNCATED"):assess([rule("deletion")]*101)
if __name__=="__main__":unittest.main()
