#!/usr/bin/env python3
"""PUBLIC-SAFE SYNTHETIC S2 contract oracle. NOT an Agent Dispatch/OPA adapter.
Models the *effective* decision boundary with fictional principals, a durable
monotonic generation floor and fail-closed freshness. No signing authority.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

class UnknownAuthority(Exception):
    pass

class GenerationFloor:
    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        try:
            obj = json.loads(self.path.read_text(encoding="utf-8"))
            if set(obj) != {"generation"} or type(obj["generation"]) is not int or obj["generation"] < 1:
                raise ValueError("invalid generation envelope")
            return obj["generation"]
        except (OSError, ValueError, TypeError) as exc:
            raise UnknownAuthority("absent, unreadable or corrupt monotonic floor") from exc

    def commit(self, generation):
        """Fixture-only atomic write, NOT a multi-process lock or secure storage."""
        if type(generation) is not int or generation < 1:
            raise UnknownAuthority("invalid proposed generation")
        try:
            old = self.read()
        except UnknownAuthority:
            # Bootstrap is explicitly distinct from normal decision evaluation.
            raise
        if generation < old:
            raise UnknownAuthority("rollback detected")
        fd, p = tempfile.mkstemp(dir=str(self.path.parent), prefix=".candidate-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump({"generation": generation}, out)
                out.flush()
                os.fsync(out.fileno())
            os.replace(p, self.path)
        finally:
            if os.path.exists(p):
                os.unlink(p)

def effective_allow(*, raw_opa_allow, generation, expiry, now, principal, workset,
                    operation, verified, floor, emergency_deny=False,
                    publisher_available=True, freshness_required=True):
    """Raw OPA ALLOW is necessary, never sufficient. No fallback on errors."""
    try:
        trusted_floor = floor.read()
    except UnknownAuthority:
        return False
    if emergency_deny or not verified or not raw_opa_allow:
        return False
    if type(generation) is not int or generation < trusted_floor:
        return False
    if type(expiry) not in (float, int) or type(now) not in (float, int) or now >= expiry:
        return False
    if freshness_required and not publisher_available:
        return False
    return (principal, workset, operation) == ("synthetic-worker", "synthetic-workset", "observe")

class SyntheticContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "generation.json"
        self.path.write_text('{"generation": 2}', encoding="utf-8")
        self.floor = GenerationFloor(self.path)
        self.args = dict(raw_opa_allow=True, generation=2, expiry=200,
                         now=100, principal="synthetic-worker",
                         workset="synthetic-workset", operation="observe",
                         verified=True, floor=self.floor)

    def test_current_approved_allow(self):
        self.assertTrue(effective_allow(**self.args))
    def test_older_valid_signed_allow_after_deny(self):
        self.assertFalse(effective_allow(**(self.args | {"generation": 1})))
    def test_raw_opa_deny(self):
        self.assertFalse(effective_allow(**(self.args | {"raw_opa_allow": False})))
    def test_unverified_bundle(self):
        self.assertFalse(effective_allow(**(self.args | {"verified": False})))
    def test_expired_policy_and_equal_boundary(self):
        for now in (200, 201):
            self.assertFalse(effective_allow(**(self.args | {"now": now})))
    def test_outage_consequential_freshness(self):
        self.assertFalse(effective_allow(**(self.args | {"publisher_available": False})))
    def test_emergency_local_deny(self):
        self.assertFalse(effective_allow(**(self.args | {"emergency_deny": True})))
    def test_exact_principal_workset_operation(self):
        for field, value in (("principal","other"),("workset","other"),("operation","actuate")):
            self.assertFalse(effective_allow(**(self.args | {field:value})))
    def test_missing_or_corrupt_floor(self):
        for bad in ("", "{}", '{"generation": 0}', '{"generation": 1.5}', '{"generation": true}', "garbage"):
            self.path.write_text(bad, encoding="utf-8")
            self.assertFalse(effective_allow(**self.args))
        self.path.unlink()
        self.assertFalse(effective_allow(**self.args))
    def test_generation_monotonic_restart(self):
        self.floor.commit(3)
        self.assertEqual(GenerationFloor(self.path).read(), 3)
        self.assertFalse(effective_allow(**self.args))
        self.assertTrue(effective_allow(**(self.args | {"generation": 3})))
        with self.assertRaises(UnknownAuthority):
            self.floor.commit(2)
        self.assertEqual(GenerationFloor(self.path).read(), 3)
    def test_no_implicit_bootstrap(self):
        self.path.unlink()
        with self.assertRaises(UnknownAuthority):
            self.floor.commit(2)
        self.assertFalse(effective_allow(**self.args))
    def test_invalid_claim_types_fail_closed(self):
        for field, value in (("generation", 2.0), ("generation", True), ("expiry", "200"), ("now", "100")):
            self.assertFalse(effective_allow(**(self.args | {field:value})))

if __name__ == "__main__":
    unittest.main(verbosity=2)
