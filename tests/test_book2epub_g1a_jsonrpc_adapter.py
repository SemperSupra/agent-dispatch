#!/usr/bin/env python3
"""B1 red/blue: JSON-RPC transport, role and read-only guardrails."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "g1a_jrpc", ROOT / "scripts" / "book2epub_g1a_jsonrpc_adapter.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def binding():
    return {
        "target": "TrueNAS-25.04.2.6", "protocol": "JSONRPC_2_0",
        "endpoint": "/api/current", "transport": "WSS_CERT_VERIFIED_BY_SESSION_OWNER",
        "role": "DOCKER_READ", "peer_cert_sha256": "a" * 64,
        "session_id": "tn-25-04-2-6-g1a-001",
    }


class Client:
    def __init__(self, version="TrueNAS-25.04.2.6", status="RUNNING", pool="rdtepool",
                 fail=None):
        self.calls = []
        self.version = version
        self.status = status
        self.pool = pool
        self.fail = fail

    def call(self, method):
        self.calls.append(method)
        if method == self.fail:
            raise PermissionError("never print API-key 123456")
        return {"system.version": self.version,
                "docker.status": {"status": self.status},
                "docker.config": {"pool": self.pool, "token": "never emit"}}[method]


class JsonRpcAdmissionTests(unittest.TestCase):
    def test_exact_read_only_sequence_does_not_self_attest(self):
        c = Client()
        r = m.observe_client(c, binding())
        self.assertEqual(c.calls, ["system.version", "docker.status", "docker.config"])
        self.assertEqual(r["classification"], "MIDDLEWARE_STATUS_OBSERVED_GUEST_UNVERIFIED")
        self.assertEqual(r["runtime_verdict"], "UNVERIFIED_CANDIDATE_ONLY")
        for k in ("independent_tls_peer_proof", "independent_role_proof",
                  "independent_guest_ownership_proof", "credential_disclosure",
                  "guest_identity_verified", "registry_trust_verified", "image_pull_verified"):
            self.assertFalse(r[k])
        self.assertNotIn("never emit", str(r))

    def test_insecure_or_unknown_transport_fails_before_network(self):
        for transport in ["WS", "PLAIN", "WSS_INSECURE", "WSS", "TLS_UNVERIFIED"]:
            with self.subTest(transport=transport):
                b = binding(); b["transport"] = transport
                c = Client()
                with self.assertRaises(m.AdmissionError):
                    m.observe_client(c, b)
                self.assertEqual(c.calls, [])

    def test_legacy_ddp_or_wrong_endpoint_no_silent_fallback(self):
        for protocol, endpoint in [("DDP", "/api/current"),
                                   ("JSONRPC_2_0", "/websocket"),
                                   ("JSONRPC_2_0", "http://127.0.0.1/api/current")]:
            with self.subTest(protocol=protocol, endpoint=endpoint):
                b = binding(); b["protocol"] = protocol; b["endpoint"] = endpoint
                c = Client()
                with self.assertRaises(m.AdmissionError):
                    m.observe_client(c, b)
                self.assertEqual(c.calls, [])

    def test_apps_read_and_admin_without_exact_role_rejected(self):
        for role in ["APPS_READ", "FULL_ADMIN", "DOCKER_WRITE", ""]:
            b = binding(); b["role"] = role
            c = Client()
            with self.subTest(role=role), self.assertRaises(m.AdmissionError):
                m.observe_client(c, b)
            self.assertEqual(c.calls, [])

    def test_unbound_peer_identity_refused(self):
        for digest in ["", "not-a-fingerprint", "A" * 64, "a" * 63]:
            b = binding(); b["peer_cert_sha256"] = digest
            c = Client()
            with self.subTest(digest=digest), self.assertRaises(m.AdmissionError):
                m.observe_client(c, b)
            self.assertEqual(c.calls, [])

    def test_target_mismatch_before_docker(self):
        c = Client(version="TrueNAS-25.10.7")
        r = m.observe_client(c, binding())
        self.assertEqual(c.calls, ["system.version"])
        self.assertEqual(r["classification"], "BLOCKED_OBSERVATION")

    def test_wrong_pinned_target_refused_before_calls(self):
        b = binding(); b["target"] = "TrueNAS-26.0.0"
        c = Client()
        with self.assertRaises(m.AdmissionError):
            m.observe_client(c, b)
        self.assertEqual(c.calls, [])

    def test_role_permission_error_sanitized(self):
        c = Client(fail="docker.status")
        r = m.observe_client(c, binding())
        self.assertEqual(r["classification"], "BLOCKED_OBSERVATION")
        self.assertNotIn("123456", str(r))
        self.assertFalse(r["independent_role_proof"])

    def test_invalid_session_identity_refused_before_calls(self):
        for sid in ["", "x", "UPPERCASE-SESSION", "../secrets"]:
            b = binding(); b["session_id"] = sid
            c = Client()
            with self.subTest(sid=sid), self.assertRaises(m.AdmissionError):
                m.observe_client(c, b)
            self.assertEqual(c.calls, [])

    def test_unknown_binding_field_cannot_amplify_authority(self):
        b = binding(); b["allow_mutation"] = True
        c = Client()
        with self.assertRaises(m.AdmissionError):
            m.observe_client(c, b)
        self.assertEqual(c.calls, [])

    def test_uninitialized_pool_and_down_service_block(self):
        for c in [Client(pool=None), Client(status="FAILED")]:
            r = m.observe_client(c, binding())
            self.assertEqual(r["classification"], "BLOCKED_OBSERVATION")
            self.assertEqual(c.calls, ["system.version", "docker.status", "docker.config"])

    def test_non_client_refused(self):
        with self.assertRaises(m.AdmissionError):
            m.observe_client(object(), binding())


if __name__ == "__main__":
    unittest.main()
