import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "book2epub_g1a_guest_observe.py"
spec = importlib.util.spec_from_file_location("g1a", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class GuestObserverTests(unittest.TestCase):
    SESSION = "Book2EPUB-G1A-20261024"

    @staticmethod
    def runner(version='"TrueNAS-SCALE-25.04.2.6"', server=None, registry=None):
        server = server or json.dumps({"Version": "28.0.0"})
        registry = registry or json.dumps({"InsecureRegistryCIDRs": ["127.0.0.0/8"]})
        def run(cmd):
            if cmd[:3] == ["midclt", "call", "system.version"]:
                return {"ok": True, "text": version}
            if cmd[:2] == ["docker", "version"]:
                return {"ok": True, "text": server}
            if cmd[:2] == ["docker", "info"]:
                return {"ok": True, "text": registry}
            raise AssertionError("Unallowed command " + str(cmd))
        return run

    def test_positive_g1a_network_only_not_trust(self):
        v = m.observe(self.SESSION, self.runner(),
                      lambda: {"reachable": True, "http_status": 200, "auth_required": False})
        self.assertEqual(v["classification"], "OBSERVED_NETWORK_ONLY_G1B_UNVERIFIED")
        for key in ("image_pull_performed", "engine_registry_trust_proven", "exact_digest_pull_proven", "book2epub_product_tested"):
            self.assertFalse(v[key])
        self.assertEqual(v["physical_truenas_apply"], "HOLD")

    def test_401_is_endpoint_not_engine_trust(self):
        v = m.observe(self.SESSION, self.runner(),
                      lambda: {"reachable": True, "http_status": 401, "auth_required": True})
        self.assertEqual(v["classification"], "OBSERVED_NETWORK_ONLY_G1B_UNVERIFIED")
        self.assertTrue(v["observations"]["gateway"]["auth_required"])
        self.assertFalse(v["engine_registry_trust_proven"])

    def test_canonical_and_legacy_target_version_variants(self):
        for version in ('"TrueNAS-25.04.2.6"', '"TrueNAS-SCALE-25.04.2.6"',
                        '"25.04.2.6"'):
            with self.subTest(version=version):
                v = m.observe(self.SESSION, self.runner(version=version),
                              lambda: {"reachable": True, "http_status": 200, "auth_required": False})
                self.assertTrue(v["observations"]["version_match"])
                self.assertEqual(v["classification"], "OBSERVED_NETWORK_ONLY_G1B_UNVERIFIED")
                self.assertFalse(v["engine_registry_trust_proven"])

    def test_build_suffix_not_the_pinned_exact_version(self):
        v = m.observe(self.SESSION, self.runner(version='"TrueNAS-25.04.2.6+unqualified"'),
                      lambda: self.fail("must not contact gateway after version drift"))
        self.assertEqual(v["classification"], "BLOCKED_OBSERVATION")
        self.assertFalse(v["observations"]["version_match"])

    def test_wrong_version_refuses_before_docker(self):
        def run(cmd):
            self.assertEqual(cmd[:2], ["midclt", "call"])
            return {"ok": True, "text": "TrueNAS-SCALE-25.10.7"}
        v = m.observe(self.SESSION, run, lambda: self.fail("network contacted"))
        self.assertEqual(v["classification"], "BLOCKED_OBSERVATION")
        self.assertFalse(v["observations"]["version_match"])

    def test_missing_midclt_refuses(self):
        v = m.observe(self.SESSION, lambda _: {"ok": False, "failure": "FileNotFoundError"},
                      lambda: self.fail("network contacted"))
        self.assertEqual(v["classification"], "BLOCKED_OBSERVATION")

    def test_missing_docker_server_refuses(self):
        v = m.observe(self.SESSION, self.runner(server='{}'),
                      lambda: self.fail("network contacted"))
        self.assertEqual(v["classification"], "BLOCKED_OBSERVATION")

    def test_malformed_docker_json_refuses(self):
        v = m.observe(self.SESSION, self.runner(registry='invalid-json'),
                      lambda: self.fail("network contacted"))
        self.assertEqual(v["classification"], "BLOCKED_OBSERVATION")

    def test_gateway_failure_cannot_look_like_success(self):
        v = m.observe(self.SESSION, self.runner(),
                      lambda: {"reachable": False, "http_status": 404, "auth_required": False})
        self.assertEqual(v["classification"], "BLOCKED_OBSERVATION")

    def test_host_loopback_or_remote_url_denied(self):
        for target in ("http://127.0.0.1:5000/v2/", "http://10.0.2.2:5001/v2/",
                       "http://example.com/v2/", "https://10.0.2.2:5000/v2/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                m.read_gateway(target)

    def test_session_identity_validation(self):
        for value in ("a", "../../etc/shadow", "with space", "x" * 100, ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.observe(value, self.runner())


if __name__ == "__main__":
    unittest.main()
