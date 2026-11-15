"""Independent adversarial checks for the fictional mail retrieval baseline."""
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import mail_synthetic_baseline as bench


class PublicSyntheticMailTests(unittest.TestCase):
    def test_deterministic_source_identity_and_replay(self):
        a, tasks = bench.build_corpus(19)
        b, later = bench.build_corpus(19)
        self.assertEqual(bench.canonical(a), bench.canonical(b))
        self.assertEqual(tasks, later)
        self.assertNotEqual(a, bench.build_corpus(21)[0])
        self.assertEqual(bench.benchmark(19)["corpus_sha256"],
                         bench.benchmark(19)["corpus_sha256"])

    def test_distinct_occurrences_even_if_same_attachment_bytes(self):
        rows, _ = bench.build_corpus()
        self.assertEqual(len(rows), 16)
        ids = [r["occurrence_id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)))
        atlas = {r["occurrence_id"]: r for r in rows}
        for lang in bench.TOPICS:
            left = atlas[f"{lang}-0-a"]
            right = atlas[f"{lang}-0-b"]
            self.assertNotEqual(left["occurrence_id"], right["occurrence_id"])
            self.assertIn(left["subject"], right["body"])
            self.assertEqual(left["attachment_occurrences"][0]["sha256"],
                             right["attachment_occurrences"][0]["sha256"])
            self.assertNotEqual(left["attachment_occurrences"][0]["occurrence_id"],
                                right["attachment_occurrences"][0]["occurrence_id"])

    def test_amended_document_is_not_silently_collapsed(self):
        rows, _ = bench.build_corpus()
        lookup = {r["occurrence_id"]: r for r in rows}
        for language in bench.TOPICS:
            a = lookup[f"{language}-1-a"]
            b = lookup[f"{language}-1-b"]
            self.assertNotEqual(a["body"], b["body"])
            self.assertNotEqual(a["attachment_occurrences"][0]["sha256"],
                                b["attachment_occurrences"][0]["sha256"])
            self.assertEqual(b["observation"], "REVISION_CANDIDATE")

    def test_colliding_internet_ids_are_not_equated(self):
        rows, _ = bench.build_corpus()
        lookup = {r["occurrence_id"]: r for r in rows}
        for language in bench.TOPICS:
            a = lookup[f"{language}-0-a"]
            other = lookup[f"{language}-2-a"]
            self.assertEqual(a["internet_message_id"],
                             other["internet_message_id"])
            self.assertNotEqual(a["subject"], other["subject"])

    def test_partial_export_absence_not_labeled_deletion(self):
        rows, _ = bench.build_corpus()
        ids = {r["occurrence_id"] for r in rows}
        for language in bench.TOPICS:
            self.assertIn(f"{language}-2-a", ids)
            self.assertNotIn(f"{language}-2-b", ids)
        self.assertTrue(all(r["observation"] != "DELETED" for r in rows))

    def test_acl_filter_and_no_cross_tenant_evidence(self):
        rows, _ = bench.build_corpus()
        db = bench.open_index(rows)
        self.assertEqual(bench.retrieve(db, "Private starling ledger", "alpha"), [])
        self.assertEqual(bench.retrieve(db, "Private starling ledger", "beta"),
                         ["beta-private-a"])

    def test_language_retrieval_and_known_scope(self):
        score = bench.benchmark()
        self.assertEqual(score["classification"], "RETRIEVAL_ONLY_SYNTHETIC")
        self.assertEqual(score["retrieval_recall_at_3"], 1)
        self.assertEqual(score["languages"], ["de", "en", "th"])
        self.assertEqual(score["queries"], 9)
        self.assertFalse(score["model_inference"])
        self.assertEqual(score["generated_answer_accuracy"], "NOT_TESTED")
        self.assertEqual(score["native_pst_conformance"], "NOT_TESTED")

    def test_thai_search_and_unknown_abstention(self):
        rows, tasks = bench.build_corpus()
        db = bench.open_index(rows)
        for task in tasks:
            if task["language"] == "th":
                self.assertTrue(bench.retrieve(db, task["query"], "alpha"))
        self.assertEqual(bench.retrieve(db, "unknown qzxv", "alpha"), [])

    def test_malicious_mail_is_data_not_an_instruction(self):
        rows, _ = bench.build_corpus()
        infected = [r for r in rows if bench.INJECTION in r["body"]]
        self.assertEqual(len(infected), 1)
        self.assertEqual(infected[0]["tenant"], "alpha")
        score = bench.benchmark()
        self.assertFalse(score["cross_tenant_leakage"])
        self.assertFalse(score["unknown_invented"])

    def test_heldout_thread_families_disjoint_from_development(self):
        _, tasks = bench.build_corpus()
        group = lambda t: t["query_id"].split("-")[-2:]
        dev = {tuple(group(t)) for t in tasks if t["partition"] == "development"}
        held = {tuple(group(t)) for t in tasks if t["partition"] == "held-out"}
        self.assertTrue(dev)
        self.assertTrue(held)
        self.assertTrue(dev.isdisjoint(held))


if __name__ == "__main__":
    unittest.main()
