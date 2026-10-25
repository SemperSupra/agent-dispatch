#!/usr/bin/env python3
"""Source-only controlled DDP adapter tests; none use a guest or credentials."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
p = ROOT / "scripts" / "book2epub_g1a_rpc_adapter.py"
spec = importlib.util.spec_from_file_location("g1a_adapter", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class AdapterTests(unittest.TestCase):
    S = "tn-25-04-2-6-g1a-001"

    def fake(self, version="TrueNAS-25.04.2.6", status="RUNNING",
             pool="rdtepool", forbidden=None):
        calls = []
        def ddp_call(ws, request_id, method, params):
            self.assertIs(ws, self)
            self.assertEqual(params, [])
            self.assertTrue(request_id.startswith("book2epub-g1a-"))
            calls.append(method)
            if method == forbidden:
                raise PermissionError("fake privileged error contains a secret")
            return {
                "system.version": version,
                "docker.status": {"status": status},
                "docker.config": {"pool": pool, "api_key": "DO_NOT_EMIT"},
            }[method]
        return ddp_call, calls

    def test_exact_three_calls_are_only_reads(self):
        transport, calls = self.fake()
        receipt = mod.observe_ddp_session(self, transport, self.S)
        self.assertEqual(calls, list(mod.READ_METHODS))
        self.assertEqual(receipt["classification"], "MIDDLEWARE_STATUS_OBSERVED_GUEST_UNVERIFIED")
        self.assertEqual(receipt["read_only_rpc_count"], 3)
        self.assertNotIn("DO_NOT_EMIT", str(receipt))

    def test_no_authority_promotion_from_synthetic_success(self):
        transport, _ = self.fake()
        receipt = mod.observe_ddp_session(self, transport, self.S)
        self.assertEqual(receipt["required_trueNAS_role"], "DOCKER_READ")
        self.assertFalse(receipt["role_assignment_proven"])
        self.assertEqual(receipt["runtime_transport_attestation"], "NOT_PROVEN_BY_THIS_ADAPTER")
        for key in ("guest_identity_verified", "network_reachability_verified",
                    "registry_trust_verified", "image_pull_verified"):
            self.assertFalse(receipt[key])
        self.assertEqual(receipt["physical_apply"], "HOLD")

    def test_version_drift_calls_only_system_version(self):
        transport, calls = self.fake(version="TrueNAS-25.04.1")
        receipt = mod.observe_ddp_session(self, transport, self.S)
        self.assertEqual(calls, ["system.version"])
        self.assertEqual(receipt["read_only_rpc_count"], 1)
        self.assertEqual(receipt["classification"], "BLOCKED_OBSERVATION")

    def test_doctor_read_permission_refusal_blocks(self):
        transport, calls = self.fake(forbidden="docker.status")
        receipt = mod.observe_ddp_session(self, transport, self.S)
        self.assertEqual(calls, ["system.version", "docker.status"])
        self.assertEqual(receipt["classification"], "BLOCKED_OBSERVATION")
        self.assertFalse(receipt["role_assignment_proven"])
        self.assertNotIn("secret", str(receipt))

    def test_docker_config_permission_refusal_blocks(self):
        transport, calls = self.fake(forbidden="docker.config")
        receipt = mod.observe_ddp_session(self, transport, self.S)
        self.assertEqual(calls, list(mod.READ_METHODS))
        self.assertEqual(receipt["classification"], "BLOCKED_OBSERVATION")

    def test_status_down_cannot_be_positive(self):
        transport, calls = self.fake(status="FAILED")
        receipt = mod.observe_ddp_session(self, transport, self.S)
        self.assertEqual(calls, list(mod.READ_METHODS))
        self.assertEqual(receipt["classification"], "BLOCKED_OBSERVATION")

    def test_empty_pool_cannot_be_positive(self):
        transport, _ = self.fake(pool=None)
        self.assertEqual(mod.observe_ddp_session(self, transport, self.S)["classification"],
                         "BLOCKED_OBSERVATION")

    def test_bad_identity_rejected_before_transport(self):
        for value in ("", "test", "with spaces 123", "TN-upper-case", "../parent"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mod.observe_ddp_session(self, lambda *_: self.fail("transport contacted"), value)

    def test_adapter_disallows_reusing_for_mutation(self):
        transport, calls = self.fake()
        mod.observe_ddp_session(self, transport, self.S)
        self.assertEqual(calls, list(mod.READ_METHODS))
        self.assertNotIn("docker.update", calls)


if __name__ == "__main__":
    unittest.main()
