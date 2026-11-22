"""Public synthetic Wyse-site boundary oracles for existing Agent Dispatch contracts.

No Wyse hardware identity, Sidecar atomic lease or privileged host is simulated as
qualified. Use the actual generic contract; never implement a second scheduler.
Authority: private infrastructure-as-code-private#337, parent #323.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import gha_assignment_contract as contract
import gha_assignment_execute as executor
import gha_workload_request as profile

SOURCE = "a" * 40
CLOCK = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)


def time_text(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def request():
    profile_id = "cpu-x64-arithmetic-v1"
    return {
        "schema": contract.SCHEMA,
        "assignment_id": "wyse-public-boundary-001",
        "nonce": "5" * 32,
        "profile_id": profile_id,
        "profile_sha256": profile.plan(contract.PROFILES[profile_id])["request_sha256"],
        "source_sha": SOURCE,
        "authority_sha256": "b" * 64,
        "issued_at": time_text(CLOCK - timedelta(seconds=10)),
        "expires_at": time_text(CLOCK + timedelta(minutes=5)),
        "data_class": "public-synthetic",
        "max_attempts": 1,
        "max_cost_usd": 0,
    }


def admit(doc, **kwargs):
    return contract.admit(json.dumps(doc), trusted_source_sha=SOURCE, now=CLOCK, **kwargs)


class WyseSyntheticAssignmentBoundary(unittest.TestCase):
    def test_valid_public_cpu_is_not_device_or_private_authority(self):
        plan = admit(request())
        self.assertEqual(plan["runner"], "ubuntu-24.04")
        self.assertEqual(plan["max_attempts"], 1)
        self.assertEqual(plan["max_cost_usd"], 0)
        self.assertEqual(plan["data_class"], "public-synthetic")
        self.assertIn("does not attest private DLE authorization", plan["limitation"])
        self.assertNotIn("chassis_id", plan)
        self.assertNotIn("authenticated_device", plan)
        self.assertNotIn("sidecar_atomic_lease", plan)

    def test_canonical_reordered_json_keeps_one_identity_digest(self):
        doc = request()
        reverse = {key: doc[key] for key in reversed(list(doc))}
        a = admit(doc)
        b = admit(reverse)
        self.assertEqual(a["assignment_sha256"], b["assignment_sha256"])

    def test_independently_observed_assignment_or_nonce_replay_denied(self):
        doc = request()
        old_id, old_nonce = doc["assignment_id"], doc["nonce"]
        for changed, prior in (
            ({"nonce": "9" * 32}, [("old-work", "1" * 32), (old_id, old_nonce)]),
            ({"assignment_id": "wyse-public-boundary-002"}, [(old_id, old_nonce)]),
            ({}, [(old_id, old_nonce)]),
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(contract.Denied, "REPLAY_OR_DUPLICATE"):
                    admit(dict(doc, **changed), prior_identities=prior)
        with self.assertRaisesRegex(contract.Denied, "REPLAY_EVIDENCE_INVALID"):
            admit(doc, prior_identities=[("malformed",)])
        # This is only a non-atomic replay check against caller-supplied proof.
        # True one-use admission must be established in authenticated Sidecar.

    def test_expiry_future_and_overlong_window_denied(self):
        doc = request()
        cases = (
            {"expires_at": time_text(CLOCK - timedelta(seconds=1))},
            {"issued_at": time_text(CLOCK + timedelta(seconds=45)),
             "expires_at": time_text(CLOCK + timedelta(minutes=6))},
            {"expires_at": time_text(CLOCK + timedelta(minutes=20))},
            {"expires_at": doc["issued_at"]},
        )
        for change in cases:
            with self.subTest(change=change), self.assertRaisesRegex(
                contract.Denied, "ASSIGNMENT_EXPIRED_OR_FUTURE|ASSIGNMENT_TTL_DENIED"
            ):
                admit(dict(doc, **change))

    def test_no_chassis_selector_or_unreviewed_executable_command(self):
        # An extra 'chassis_id' is not an authenticated identity binding.
        # All such fields are outside the public CPU schema and must be denied.
        for field, value in (
            ("chassis_id", "test-wyse-001"),
            ("device_id", "test-wyse-001"),
            ("host", "192.0.2.1"),
            ("command", "id"),
            ("runner", "self-hosted"),
            ("ssh_key", "dummy-value"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                contract.Denied, "ASSIGNMENT_FIELDS_DENIED"
            ):
                admit(dict(request(), **{field: value}))

    def test_cost_scope_source_profile_and_attempt_fail_closed(self):
        doc = request()
        cases = (
            ({"data_class": "private"}, "PRIVATE_DATA_DENIED"),
            ({"max_cost_usd": 1}, "COST_LIMIT_DENIED"),
            ({"max_cost_usd": False}, "COST_LIMIT_DENIED"),
            ({"max_attempts": 2}, "ATTEMPT_LIMIT_DENIED"),
            ({"source_sha": "c" * 40}, "SOURCE_DRIFT"),
            ({"profile_sha256": "d" * 64}, "PROFILE_DIGEST_DRIFT"),
            ({"profile_id": "wyse-native-device-executor"}, "PROFILE_ID_DENIED"),
        )
        for change, marker in cases:
            with self.subTest(change=change), self.assertRaisesRegex(contract.Denied, marker):
                admit(dict(doc, **change))

    def test_duplicate_json_fields_fail_before_execution(self):
        original = json.dumps(request())
        duplicate = original[:-1] + ', "nonce": "' + "a" * 32 + '"}'
        with self.assertRaisesRegex(contract.Denied, "DUPLICATE_ASSIGNMENT_FIELD"):
            contract.admit(duplicate, trusted_source_sha=SOURCE, now=CLOCK)

    def test_invalid_public_envelopes_cannot_invoke_executor(self):
        doc = request()
        invalid = (
            dict(doc, data_class="private"),
            dict(doc, max_attempts=2),
            dict(doc, chassis_id="test-wyse-001"),
            dict(doc, source_sha="c" * 40),
        )
        # Real GHA execute.run checks actual current UTC. Make all requests
        # invalid independent of the current wall clock.
        with patch.object(profile, "run", side_effect=AssertionError("workload executed")) as runner:
            for payload in invalid:
                with self.subTest(payload=payload):
                    with self.assertRaises(contract.Denied):
                        executor.run(json.dumps(payload), SOURCE, "f" * 64)
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
