"""Dynamic DLE assignment -> fixed CPU profile -> native v2 receipt adversarial reps."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gha_assignment_contract as contract
import gha_assignment_execute as execute
import gha_workload_request as profile
import verify_gha_assignment_receipt as verifier

SOURCE = "a" * 40
RUN_ID = "38544093548"


def fresh(profile_id="cpu-x64-arithmetic-v1"):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "schema": contract.SCHEMA,
        "assignment_id": "gha-cpu-integ-test-001",
        "nonce": "5" * 32,
        "profile_id": profile_id,
        "profile_sha256": profile.plan(contract.PROFILES[profile_id])["request_sha256"],
        "source_sha": SOURCE,
        "authority_sha256": "b" * 64,
        "issued_at": (now-timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now+timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_class": "public-synthetic",
        "max_attempts": 1,
        "max_cost_usd": 0,
    }


def built(profile_id="cpu-x64-arithmetic-v1"):
    envelope = fresh(profile_id)
    raw = json.dumps(envelope, sort_keys=True)
    plan = execute.plan(raw, SOURCE)
    machine = "aarch64" if profile_id == "cpu-arm64-contract-v1" else "x86_64"
    runner_arch = "X64" if machine == "x86_64" else "ARM64"
    if profile_id == "microsoft-devproxy-mock-v1":
        fixed_result = {
            "oracle_verified": True, "classification": "PASS",
            "mock_only": True, "provider_access_verified": False,
            "verdict_sha256": "c" * 64,
        }
    elif profile_id == "cpu-x64-arithmetic-v1":
        fixed_result = profile._execute("arithmetic-oracle", 30)
    else:
        fixed_result = {"oracle_verified": True, "classification": "PASS"}
    with patch.object(profile.platform, "system", return_value="Linux"), \
         patch.object(profile.platform, "machine", return_value=machine), \
         patch.object(profile, "_execute", return_value=fixed_result), \
         patch.dict(os.environ, {"RUNNER_ARCH": runner_arch,
                                "GITHUB_SHA": SOURCE, "GITHUB_RUN_ID": RUN_ID,
                                "GITHUB_RUN_ATTEMPT": "1"}):
        result = execute.run(raw, SOURCE, plan["assignment_sha256"])
    encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    return raw, plan, result, encoded


def check(raw, receipt, runner, **kwargs):
    return verifier.evaluate(
        assignment_json=raw, receipt_bytes=receipt, trusted_source_sha=SOURCE,
        trusted_run_id=RUN_ID, trusted_runner=runner,
        trusted_receipt_sha256=hashlib.sha256(receipt).hexdigest(), **kwargs)


class AssignmentExecutionTests(unittest.TestCase):
    def test_native_two_shapes_have_independent_v2_oracle(self):
        for profile_id in contract.PROFILES:
            with self.subTest(profile=profile_id):
                raw, p, receipt, encoded = built(profile_id)
                self.assertEqual(receipt["schema"], execute.RECEIPT_V2)
                self.assertNotIn("nonce", receipt)
                self.assertEqual(receipt["assignment_id"], "gha-cpu-integ-test-001")
                v = check(raw, encoded, p["runner"])
                self.assertEqual(v["classification"], "PASS")
                self.assertEqual(v["assignment_sha256"], p["assignment_sha256"])
                self.assertEqual(v["receipt_sha256"], hashlib.sha256(encoded).hexdigest())
                self.assertEqual(v["native_run_id"], RUN_ID)

    def test_digest_drift_rejected_before_cpu_execution(self):
        raw, p, receipt, encoded = built()
        with patch.object(profile, "run", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex(contract.Denied, "ASSIGNMENT_DIGEST_DRIFT"):
                execute.run(raw, SOURCE, "f"*64)
            with self.assertRaisesRegex(contract.Denied, "SOURCE_DRIFT"):
                execute.run(raw, "c"*40, p["assignment_sha256"])

    def test_native_oracle_rejects_metadata_and_receipt_forgery(self):
        raw, p, receipt, encoded = built()
        for changes in (
            {"assignment_id": "different-id"},
            {"nonce_sha256": "f"*64},
            {"authority_sha256": "f"*64},
            {"assignment_sha256": "f"*64},
            {"run_attempt": "2"},
            {"source_sha": "c"*40},
            {"observed_architecture": "aarch64"},
            {"qualified": False},
            {"result": dict(receipt["result"], task_count=257)},
            {"unexpected_command": "echo secret"},
        ):
            with self.subTest(changes=changes):
                modified = dict(receipt, **changes)
                corrupted = json.dumps(modified).encode()
                with self.assertRaises((contract.Denied, verifier.base.VerdictError)):
                    check(raw, corrupted, p["runner"])
        with self.assertRaisesRegex(verifier.base.VerdictError, "NATIVE_RUNNER_LABEL_MISMATCH"):
            check(raw, encoded, "ubuntu-24.04-arm")
        with self.assertRaisesRegex(verifier.base.VerdictError, "RECEIPT_ARTIFACT_HASH_MISMATCH"):
            verifier.evaluate(
                assignment_json=raw, receipt_bytes=encoded + b" ",
                trusted_source_sha=SOURCE, trusted_run_id=RUN_ID,
                trusted_runner=p["runner"],
                trusted_receipt_sha256=hashlib.sha256(encoded).hexdigest())


    def test_historical_oracle_remains_replayable_after_assignment_expiry(self):
        raw, p, receipt, encoded = built()
        recorded = json.loads(raw)
        trusted_created = recorded["issued_at"]
        expired_clock = datetime.strptime(
            recorded["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc) + timedelta(days=7)
        with self.assertRaisesRegex(contract.Denied, "ASSIGNMENT_EXPIRED_OR_FUTURE"):
            check(raw, encoded, p["runner"], now=expired_clock)
        verified = check(
            raw, encoded, p["runner"], trusted_native_created_at=trusted_created)
        self.assertEqual(verified["classification"], "PASS")
        self.assertEqual(verified["admission_time_basis"], "provider-native-run-created-at")
        self.assertEqual(verified["trusted_native_created_at"], trusted_created)

    def test_historical_run_cannot_precede_issue_or_follow_expiry(self):
        raw, p, receipt, encoded = built()
        recorded = json.loads(raw)
        start = datetime.strptime(
            recorded["issued_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        for native_time in (
            (start - timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            recorded["expires_at"],
        ):
            with self.subTest(native_time=native_time), self.assertRaisesRegex(
                contract.Denied, "ASSIGNMENT_EXPIRED_OR_FUTURE"
            ):
                check(raw, encoded, p["runner"],
                      trusted_native_created_at=native_time)

    def test_malformed_or_conflicting_native_time_fails_closed(self):
        raw, p, receipt, encoded = built()
        for value in ("yesterday", "2026-10-14T16:00:00+00:00", "2026-13-14T16:00:00Z"):
            with self.subTest(value=value), self.assertRaisesRegex(
                verifier.base.VerdictError, "NATIVE_CREATED_AT_INVALID"
            ):
                check(raw, encoded, p["runner"], trusted_native_created_at=value)
        with self.assertRaisesRegex(
            verifier.base.VerdictError, "AMBIGUOUS_TRUSTED_TIME"
        ):
            check(raw, encoded, p["runner"], now=datetime.now(timezone.utc),
                  trusted_native_created_at=json.loads(raw)["issued_at"])

    def test_legacy_v1_stays_valid(self):
        self.assertEqual(profile.plan("requests/gha/cpu-x64-arithmetic-v1.json")["runner"], "ubuntu-24.04")
        self.assertEqual(profile.plan("requests/gha/cpu-arm64-contract-v1.json")["runner"], "ubuntu-24.04-arm")

    def test_denied_extra_cmd_never_reaches_profile(self):
        doc = fresh()
        doc["command"] = "curl example.com"
        with patch.object(profile, "run", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex(contract.Denied, "ASSIGNMENT_FIELDS_DENIED"):
                execute.run(json.dumps(doc), SOURCE, "f"*64)


if __name__ == "__main__":
    unittest.main()
