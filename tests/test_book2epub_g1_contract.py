#!/usr/bin/env python3
"""B0 evidentiary contract red/blue tests: safe for public CI."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts" / "book2epub_g1_contract.py"
spec = importlib.util.spec_from_file_location("g1_contract", PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def valid():
    sha = "a" * 40
    return {
        "schema": "book2epub-pre-admission-evidence/v1",
        "session_id": "tn-25-04-2-6-g1a-001",
        "target": "TrueNAS-25.04.2.6",
        "source_sha": sha,
        "evidence": [{
            "id": "ci-unit-001", "kind": "source_unit", "actor": "independent-validator",
            "result": "PASS",
            "ref": "https://github.com/SemperSupra/agent-dispatch/actions/runs/40148711759",
            "source_sha": sha,
        }],
    }


class EvidenceContractTests(unittest.TestCase):
    def test_reported_pass_is_never_independent_acceptance(self):
        out = m.assess(valid())
        self.assertEqual(out["contract_validation"], "VALID")
        self.assertEqual(out["qualification"], "EXTERNAL_EVIDENCE_NOT_INDEPENDENTLY_VERIFIED")
        self.assertFalse(out["dispatch_authorized"])
        self.assertFalse(out["release_authorized"])
        self.assertTrue(all(x["state"] == "HOLD" for x in out["all_gates"].values()))
        self.assertEqual(out["reported_evidence"][0]["verification"], "EXTERNAL_VALIDATION_NOT_PERFORMED")

    def test_empty_evidence_does_not_infer_success(self):
        d = valid(); d["evidence"] = []
        out = m.assess(d)
        self.assertEqual(out["evidence_count"], 0)
        self.assertEqual(out["all_gates"]["g1a"]["state"], "HOLD")

    def test_all_highest_tiers_still_unverified(self):
        d = valid(); d["evidence"] = []
        for i, kind in enumerate(sorted(m.KIND)):
            d["evidence"].append({
                "id": f"evidence-{i}", "kind": kind, "actor": "independent-validator",
                "result": "PASS", "ref": "https://github.com/SemperSupra/agent-dispatch/pull/544",
                "source_sha": d["source_sha"],
            })
        out = m.assess(d)
        self.assertFalse(out["dispatch_authorized"])
        self.assertTrue(all(v["state"] == "HOLD" for v in out["all_gates"].values()))

    def test_duplicate_replay_is_refused(self):
        d = valid(); d["evidence"].append(dict(d["evidence"][0]))
        with self.assertRaisesRegex(m.ContractError, "duplicate_evidence_id"):
            m.assess(d)

    def test_inconsistent_source_revision_is_refused(self):
        d = valid(); d["evidence"][0]["source_sha"] = "b" * 40
        with self.assertRaisesRegex(m.ContractError, "mixed_source_revision"):
            m.assess(d)

    def test_other_guest_cannot_self_promote(self):
        d = valid(); d["target"] = "TrueNAS-25.10.7"
        with self.assertRaises(m.ContractError):
            m.assess(d)

    def test_raw_model_or_secret_bytes_rejected(self):
        d = valid(); d["api_key"] = "NEVER_EXPOSE"
        with self.assertRaises(m.ContractError):
            m.assess(d)
        d = valid(); d["evidence"][0]["model_bytes"] = "NEVER_EXPOSE"
        with self.assertRaises(m.ContractError):
            m.assess(d)

    def test_unsafe_urls_markup_and_floating_sha_refused(self):
        for ref in ["http://example.com", "javascript:alert(1)",
                    "https://github.com/SemperSupra/agent-dispatch/actions/runs/latest",
                    "https://github.com/a/b/issues/2?token=secret"]:
            with self.subTest(ref=ref):
                d = valid(); d["evidence"][0]["ref"] = ref
                with self.assertRaises(m.ContractError):
                    m.assess(d)
        d = valid(); d["source_sha"] = "main"
        with self.assertRaises(m.ContractError):
            m.assess(d)

    def test_unknown_authorization_or_rogue_actor_refused(self):
        for bad in ["apply", "authorized", "session-owner"]:
            d = valid(); d["evidence"][0]["actor"] = bad
            with self.assertRaises(m.ContractError):
                m.assess(d)
        d = valid(); d["dispatch_authorized"] = True
        with self.assertRaises(m.ContractError):
            m.assess(d)

    def test_long_evidence_refused(self):
        d = valid(); d["evidence"] = [dict(d["evidence"][0], id=f"item-{i}") for i in range(25)]
        with self.assertRaises(m.ContractError):
            m.assess(d)

    def test_reordered_keys_do_not_change_digest(self):
        d = valid(); r = m.assess(d)
        shuffled = dict(reversed(list(d.items())))
        self.assertEqual(r["input_sha256"], m.assess(shuffled)["input_sha256"])

    def test_three_audience_outputs_share_one_reducer(self):
        status = m.assess(valid())
        raw = json.dumps(status, sort_keys=True)
        human = m.human_text(status)
        md = m.human_text(status, markdown=True)
        for gate in status["all_gates"]:
            self.assertIn(gate.upper(), human)
            self.assertIn(gate.upper(), md)
        self.assertIn("HOLD", raw)
        self.assertIn("HOLD", human)
        self.assertIn("HOLD", md)
        self.assertIn("unverified", human.lower())
        self.assertIn("unverified", md.lower())
        self.assertIn("Next:", human)
        self.assertIn("Next admissible step", md)

    def test_invalid_status_cannot_be_rendered(self):
        with self.assertRaises(m.ContractError):
            m.human_text({"schema": m.OUTPUT_SCHEMA, "qualification": "VERIFIED"})

    def test_cli_views_are_read_only_and_failure_is_sanitized(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "receipt.json"
            path.write_text(json.dumps(valid()))
            for fmt in ("json", "text", "markdown"):
                cp = subprocess.run([sys.executable, str(PATH), "--file", str(path),
                                     "--format", fmt], capture_output=True, text=True)
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertIn("HOLD", cp.stdout)
            path.write_text(json.dumps({"password": "SHOULD_NOT_APPEAR"}))
            cp = subprocess.run([sys.executable, str(PATH), "--file", str(path)],
                                capture_output=True, text=True)
            self.assertEqual(cp.returncode, 2)
            self.assertNotIn("SHOULD_NOT_APPEAR", cp.stderr)


if __name__ == "__main__":
    unittest.main()
