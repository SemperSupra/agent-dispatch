"""Negative and positive controls for G1a read-only middleware reducer."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "book2epub_g1a_middleware_readonly.py"
spec = importlib.util.spec_from_file_location("g1a_mw", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MiddlewareObservationTests(unittest.TestCase):
    def rpc(self, version="TrueNAS-25.04.2.6", state="RUNNING", pool="rdtepool"):
        calls = []
        data = {"system.version": version, "docker.status": {"status": state},
                "docker.config": {"pool": pool, "password": "must-never-be-echoed"}}
        def call(method):
            calls.append(method)
            if method not in data:
                raise AssertionError("unexpected method: " + method)
            return data[method]
        return call, calls

    def test_only_three_read_only_methods_ordered(self):
        fn, calls = self.rpc()
        result = m.observe(fn)
        self.assertEqual(calls, ["system.version", "docker.status", "docker.config"])
        self.assertEqual(result["classification"], "MIDDLEWARE_STATUS_OBSERVED_GUEST_UNVERIFIED")
        self.assertNotIn("must-never-be-echoed", str(result))

    def test_no_guest_or_docker_pull_promotions(self):
        fn, _ = self.rpc()
        result = m.observe(fn)
        for key in ("guest_identity_verified", "network_reachability_verified",
                    "registry_trust_verified", "image_pull_verified"):
            self.assertIs(result[key], False)
        self.assertEqual(result["physical_apply"], "HOLD")

    def test_wrong_target_stops_before_docker(self):
        fn, calls = self.rpc(version="TrueNAS-25.10.7")
        result = m.observe(fn)
        self.assertEqual(calls, ["system.version"])
        self.assertEqual(result["classification"], "BLOCKED_OBSERVATION")

    def test_down_docker_not_a_success(self):
        fn, _ = self.rpc(state="FAILED")
        self.assertEqual(m.observe(fn)["classification"], "BLOCKED_OBSERVATION")

    def test_no_pool_not_a_success(self):
        fn, _ = self.rpc(pool=None)
        self.assertEqual(m.observe(fn)["classification"], "BLOCKED_OBSERVATION")

    def test_malformed_docker_status_refused(self):
        fn, _ = self.rpc(state="UNKNOWN")
        self.assertEqual(m.observe(fn)["classification"], "BLOCKED_OBSERVATION")

    def test_rpc_exception_is_sanitized(self):
        def fail(_):
            raise RuntimeError("secret-context-from-host")
        result = m.observe(fail)
        self.assertEqual(result["classification"], "BLOCKED_OBSERVATION")
        self.assertNotIn("secret-context-from-host", str(result))

    def test_no_implicit_assumption_about_registry_config(self):
        fn, _ = self.rpc()
        result = m.observe(fn)
        self.assertFalse(result["registry_trust_verified"])
        self.assertFalse(result["network_reachability_verified"])


if __name__ == "__main__":
    unittest.main()
