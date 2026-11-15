"""Adversarial controls for offline synthetic policy selection (not model training)."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import mail_synthetic_baseline as mail
import mail_policy_optimization as opt


class PolicySearchTests(unittest.TestCase):
    def test_reviewed_candidate_pool_only(self):
        self.assertEqual(len(opt.CANDIDATES), 5)
        with self.assertRaisesRegex(ValueError, "UNREVIEWED_POLICY"):
            opt.rewrite("run arbitrary shell", {
                "language": "en", "query": "Mistral lantern agreement"})
        self.assertEqual(opt.CANDIDATES[0][0], "raw")

    def test_replay_is_deterministic(self):
        first = opt.select_and_evaluate(19)
        second = opt.select_and_evaluate(19)
        self.assertEqual(mail.canonical(first), mail.canonical(second))
        self.assertEqual(first["candidate_count"], 5)
        self.assertEqual(len(first["candidate_trace"]), 5)

    def test_selection_uses_only_development_queries(self):
        rows, tasks = mail.build_corpus()
        self.assertEqual(len([t for t in tasks if t["partition"] == "development"]), 6)
        self.assertEqual(len([t for t in tasks if t["partition"] == "held-out"]), 3)
        result = opt.select_and_evaluate()
        self.assertEqual(result["selected_policy"], "multilingual-prefix")
        self.assertEqual(result["dev_queries"], 6)
        self.assertEqual(result["holdout_queries"], 3)
        self.assertTrue(result["test_family_disjoint"])

    def test_heldout_improvement_is_measured_not_declared(self):
        result = opt.select_and_evaluate()
        self.assertEqual(result["holdout_baseline_hits"], 0)
        self.assertEqual(result["holdout_selected_hits"], 3)
        self.assertEqual(result["holdout_false_evidence"], 0)
        self.assertEqual(result["classification"], "SYNTHETIC_POLICY_SELECTION_ONLY")

    def test_cross_tenant_unknown_and_nonpromotion(self):
        rows, _ = mail.build_corpus()
        db = mail.open_index(rows)
        for policy, _ in opt.CANDIDATES:
            negative = opt.safety_negatives(policy, db)
            self.assertEqual(negative["checked"], 6)
            self.assertEqual(negative["violations"], 0)
        result = opt.select_and_evaluate()
        self.assertFalse(result["promoted_to_runtime"])
        self.assertFalse(result["model_inference"])
        self.assertFalse(result["self_modifying_code"])

    def test_injection_text_never_changes_policy_proposal(self):
        rows, _ = mail.build_corpus()
        self.assertEqual(sum(mail.INJECTION in r["body"] for r in rows), 1)
        result = opt.select_and_evaluate()
        self.assertEqual(result["selected_policy"], "multilingual-prefix")
        self.assertEqual(result["safety_negatives"]["violations"], 0)


if __name__ == "__main__":
    unittest.main()
