"""CPU public-safe typed request acceptance and adversarial negative controls."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "scripts" / "gha_workload_request.py"
spec = importlib.util.spec_from_file_location("gha_workload_request", SRC)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
X64 = "requests/gha/cpu-x64-arithmetic-v1.json"
ARM = "requests/gha/cpu-arm64-contract-v1.json"


class TypedWorkRequestTests(unittest.TestCase):
    def test_existing_two_shapes_are_admitted(self):
        first, second = m.plan(X64), m.plan(ARM)
        self.assertEqual(first["runner"], "ubuntu-24.04")
        self.assertEqual(second["runner"], "ubuntu-24.04-arm")
        self.assertEqual(first["max_cost_usd"], second["max_cost_usd"])
        self.assertEqual(first["max_cost_usd"], 0)
        self.assertEqual(first["max_attempts"], 1)
        self.assertEqual(first, m.plan(X64))
        self.assertEqual(len(first["request_sha256"]), 64)

    def test_no_unreviewed_paths_or_urls(self):
        for bad in ("../secrets.env", "requests/gha/../private.json",
                    "/tmp/public.json", "http://example.test/run.json",
                    "requests/gha/test.yml", "requests/gha/n.json",
                    "requests/gha/a;echo-b.json"):
            with self.subTest(path=bad), self.assertRaises(m.Denied):
                m.plan(bad)

    def test_request_mutations_denied(self):
        source, _ = m.read_request(X64)
        examples = [
            {"runner":"windows-11-arm"},
            {"runner":[]},
            {"workload":"run-shell"},
            {"workload":{}},
            {"execute":"curl attacker.test"},
            {"max_cost_usd":1},
            {"max_attempts":2},
            {"max_attempts":True},
            {"timeout_seconds":241},
            {"timeout_seconds":True},
            {"data_class":"private-holdout"},
            {"assignment_id":"../private"},
            {"schema":"unknown/v0"},
        ]
        for mutation in examples:
            with self.subTest(value=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                dest = root/"requests"/"gha"
                dest.mkdir(parents=True)
                data=dict(source)
                data.update(mutation)
                (dest/"cpu-test.json").write_text(json.dumps(data),encoding="utf-8")
                with patch.object(m,"ROOT",root), patch.object(m,"REQUEST_DIR",dest):
                    with self.assertRaises(m.Denied):
                        m.plan("requests/gha/cpu-test.json")

    def test_digest_bind_rejects_drift(self):
        result = m.plan(X64)
        with self.assertRaisesRegex(m.Denied,"REQUEST_DIGEST_CHANGED"):
            m.run(X64, "0"*64)
        with self.assertRaisesRegex(m.Denied,"REQUEST_DIGEST_CHANGED"):
            m.run(X64, "hello")
        self.assertEqual(result["request_sha256"], m.plan(X64)["request_sha256"])

    def test_shape_absence_is_not_capability_pass(self):
        first=m.plan(X64)
        with patch.object(m.platform,"system",return_value="Linux"), \
             patch.object(m.platform,"machine",return_value="x86_64"), \
             patch.dict(m.os.environ,{"RUNNER_ARCH":"ARM64"}):
            receipt=m.run(X64, first["request_sha256"])
        self.assertFalse(receipt["qualified"])
        self.assertEqual(receipt["result"]["classification"],"FAIL_RUNNER_SHAPE")
        self.assertFalse(receipt["shape_verified"])

    def test_arithmetic_oracle_matched(self):
        d=m._execute("arithmetic-oracle",30)
        self.assertTrue(d["oracle_verified"])
        self.assertEqual(d["classification"],"PASS")
        self.assertEqual(d["task_count"],256)
        self.assertEqual(len(d["fixture_sha256"]),64)

    def test_non_shell_backend(self):
        source=SRC.read_text()
        self.assertNotIn("shell=True",source)
        self.assertNotIn("eval(",source)
        self.assertNotIn("exec(",source)
        self.assertIn('"arithmetic-oracle"',source)
        self.assertIn('"sealed-contract-native"',source)

    def test_symlink_source_is_not_admitted(self):
        source, _ = m.read_request(X64)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            dest=root/"requests"/"gha"
            dest.mkdir(parents=True)
            outside=root/"unreviewed.json"
            outside.write_text(json.dumps(source))
            (dest/"cpu-test.json").symlink_to(outside)
            with patch.object(m,"ROOT",root), patch.object(m,"REQUEST_DIR",dest):
                with self.assertRaisesRegex(m.Denied,"REQUEST_NOT_REVIEWED_LOCAL_FILE"):
                    m.plan("requests/gha/cpu-test.json")



# V2 assignment profile separation: tested against the same reviewed on-disk
# profiles, with zero GitHub credentials, Sidecar authority, or runner budget.
spec2 = importlib.util.spec_from_file_location(
    "gha_assignment_contract", ROOT / "scripts" / "gha_assignment_contract.py")
a = importlib.util.module_from_spec(spec2)
sys.modules[spec2.name] = a
spec2.loader.exec_module(a)
from datetime import datetime, timezone, timedelta

NOW = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
SOURCE = "a" * 40


def sample(profile_id="cpu-x64-arithmetic-v1"):
    p = m.plan(a.PROFILES[profile_id])
    return {
        "schema": "gha-typed-assignment/v1",
        "assignment_id": "test-delegated-cpu-001",
        "nonce": "1" * 32,
        "profile_id": profile_id,
        "profile_sha256": p["request_sha256"],
        "source_sha": SOURCE,
        "authority_sha256": "b" * 64,
        "issued_at": "2026-10-14T15:59:00Z",
        "expires_at": "2026-10-14T16:09:00Z",
        "data_class": "public-synthetic",
        "max_attempts": 1,
        "max_cost_usd": 0,
    }


def admit_sample(data, **kwargs):
    return a.admit(json.dumps(data), trusted_source_sha=SOURCE, now=NOW, **kwargs)


class DynamicAssignmentContractTests(unittest.TestCase):
    def test_both_reviewed_profiles_and_canonical_identity(self):
        for profile_id, runner in (("cpu-x64-arithmetic-v1", "ubuntu-24.04"),
                                   ("cpu-arm64-contract-v1", "ubuntu-24.04-arm")):
            with self.subTest(profile=profile_id):
                doc = sample(profile_id)
                accepted = admit_sample(doc)
                self.assertEqual(accepted["runner"], runner)
                self.assertEqual(accepted["data_class"], "public-synthetic")
                self.assertEqual(accepted["max_attempts"], 1)
                self.assertEqual(accepted["max_cost_usd"], 0)
                other = a.admit(json.dumps(doc, indent=2), trusted_source_sha=SOURCE, now=NOW)
                self.assertEqual(accepted["assignment_sha256"], other["assignment_sha256"])

    def test_extra_fields_and_privilege_smuggling_denied(self):
        for field, val in (("command", "echo secret"), ("script", "curl example.org"),
                           ("runner", "self-hosted"), ("workflow", "other.yml"),
                           ("url", "https://example.org"), ("secret", "credential"),
                           ("scope", "admin"), ("ref", "feature-branch")):
            with self.subTest(field=field):
                doc = sample()
                doc[field] = val
                with self.assertRaisesRegex(a.Denied, "ASSIGNMENT_FIELDS_DENIED"):
                    admit_sample(doc)

    def test_wrong_id_profile_digest_and_privacy_denied(self):
        cases = [
            ({"assignment_id": "../escape"}, "ASSIGNMENT_ID_DENIED"),
            ({"nonce": "x"*32}, "ASSIGNMENT_NONCE_DENIED"),
            ({"profile_id": "cpu-win-shell"}, "PROFILE_ID_DENIED"),
            ({"profile_id": []}, "PROFILE_ID_DENIED"),
            ({"profile_id": {}}, "PROFILE_ID_DENIED"),
            ({"profile_sha256": "f"*64}, "PROFILE_DIGEST_DRIFT"),
            ({"source_sha": "c"*40}, "SOURCE_DRIFT"),
            ({"data_class": "private"}, "PRIVATE_DATA_DENIED"),
            ({"max_attempts": 2}, "ATTEMPT_LIMIT_DENIED"),
            ({"max_attempts": True}, "ATTEMPT_LIMIT_DENIED"),
            ({"max_cost_usd": 0.01}, "COST_LIMIT_DENIED"),
            ({"max_cost_usd": True}, "COST_LIMIT_DENIED"),
            ({"authority_sha256": "bogus"}, "ASSIGNMENT_DIGEST_INVALID"),
        ]
        for mutation, reason in cases:
            with self.subTest(case=mutation), self.assertRaisesRegex(a.Denied, reason):
                admit_sample(dict(sample(), **mutation))

    def test_stale_future_and_long_lifetime_denied(self):
        for mutation, reason in (
            ({"expires_at": "2026-10-14T15:59:59Z"}, "ASSIGNMENT_EXPIRED_OR_FUTURE"),
            ({"issued_at": "2026-10-14T16:02:00Z"}, "ASSIGNMENT_EXPIRED_OR_FUTURE"),
            ({"expires_at": "2026-10-14T17:00:00Z"}, "ASSIGNMENT_TTL_DENIED"),
            ({"expires_at": "2026-10-14T15:00:00Z"}, "ASSIGNMENT_TTL_DENIED"),
            ({"issued_at": "2026-10-14 15:59:00"}, "ASSIGNMENT_TIMESTAMP_INVALID"),
        ):
            with self.subTest(case=mutation), self.assertRaisesRegex(a.Denied, reason):
                admit_sample(dict(sample(), **mutation))

    def test_independent_replay_identity_required(self):
        doc = sample()
        for prior in ([("test-delegated-cpu-001", "f"*32)],
                      [("another-assignment", "1"*32)]):
            with self.subTest(prior=prior), self.assertRaisesRegex(a.Denied, "REPLAY_OR_DUPLICATE"):
                admit_sample(doc, prior_identities=prior)
        with self.assertRaisesRegex(a.Denied, "REPLAY_EVIDENCE_INVALID"):
            admit_sample(doc, prior_identities=[None])

    def test_duplicate_json_and_bounded_untrusted_input(self):
        raw = json.dumps(sample())
        forged = raw.replace('"max_attempts": 1', '"max_attempts": 1, "max_attempts": 1')
        with self.assertRaisesRegex(a.Denied, "DUPLICATE_ASSIGNMENT_FIELD"):
            a.admit(forged, trusted_source_sha=SOURCE, now=NOW)
        with self.assertRaisesRegex(a.Denied, "ASSIGNMENT_BYTES_INVALID"):
            a.admit(raw + " " * 5000, trusted_source_sha=SOURCE, now=NOW)

    def test_zero_new_scheduler_or_shell_authority(self):
        source = (ROOT / "scripts" / "gha_assignment_contract.py").read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("subprocess.run", source)
        self.assertNotIn("workflow_dispatch(", source)


if __name__=="__main__":
    unittest.main()
