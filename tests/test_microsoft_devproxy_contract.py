"""Independent credential-free Microsoft Dev Proxy contract negative tests."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "scripts/microsoft_devproxy_contract.py"
spec = importlib.util.spec_from_file_location("microsoft_devproxy_contract", SRC)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class MicrosoftProxyTests(unittest.TestCase):
    def test_exact_mock_contract_and_digest(self):
        first = m.validate_fixtures()
        self.assertEqual(first, m.validate_fixtures())
        self.assertEqual(len(first), 64)
        self.assertEqual(len(m.EXPECTED), 8)
        self.assertNotIn("https://graph.microsoft.com", SRC.read_text())

    def test_meaningful_different_errors(self):
        self.assertEqual(m.classify(403, {
            "error":{"code":"accessDenied","innerError":{"code":"serviceReadOnly"}}
        }, {}), "PROVIDER_PROVISIONING_CANDIDATE")
        self.assertEqual(m.classify(403, {
            "error":{"code":"accessDenied"}
        }, {}).__class__, str) if False else None
        with self.assertRaisesRegex(m.Denied, "UNRECOGNIZED_RESPONSE"):
            m.classify(403, {"error":{"code":"accessDenied"}}, {})

    def test_retry_bounds(self):
        self.assertEqual(m.classify(429, {}, {"Retry-After":"2"}), "RETRY_BOUNDED")
        for bad in ("0"*80, "999", "5000", "3.5", "-1", "NaN"):
            self.assertEqual(m.classify(429, {}, {"Retry-After":bad}), "RETRY_DENIED")
        self.assertEqual(m.classify(429, {}, {}), "RETRY_DENIED")

    def test_malformed_and_implicit_success(self):
        for case in [(200,{}), (200,{"token":"mock"}), (201,{"item":{}}),
                     (403,{"error":{"code":"accessDenied","innerError":{}}}),
                     (500,{"error":{"code":"internalServerError"}})]:
            with self.subTest(case=case), self.assertRaises(m.Denied):
                m.classify(*case, {})
        with self.assertRaises(m.Denied):
            m.classify(True, {}, {})

    def test_detect_pass_through_and_forged_fixture_url(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            shutil.copytree(m.FIXTURES, folder/"fixtures")
            cfg = folder/"fixtures"/"devproxyrc.json"
            obj = json.loads(cfg.read_text())
            obj["mockResponsePlugin"]["blockUnmockedRequests"] = False
            cfg.write_text(json.dumps(obj))
            with patch.object(m, "FIXTURES", folder/"fixtures"):
                with self.assertRaisesRegex(m.Denied, "UNMOCKED_PASS_THROUGH"):
                    m.validate_fixtures()
            obj["mockResponsePlugin"]["blockUnmockedRequests"] = True
            obj["urlsToWatch"] = ["https://graph.microsoft.com/*"]
            cfg.write_text(json.dumps(obj))
            with patch.object(m, "FIXTURES", folder/"fixtures"):
                with self.assertRaisesRegex(m.Denied, "UNEXPECTED_WATCH_TARGET"):
                    m.validate_fixtures()

    def test_reject_token_and_duplicate_mock(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            shutil.copytree(m.FIXTURES, folder/"fixtures")
            p = folder/"fixtures"/"mocks.json"
            obj = json.loads(p.read_text())
            obj["mocks"].append(obj["mocks"][0])
            p.write_text(json.dumps(obj))
            with patch.object(m, "FIXTURES", folder/"fixtures"):
                with self.assertRaisesRegex(m.Denied, "UNEXPECTED_CASE"):
                    m.validate_fixtures()
            p.write_text(p.read_text().replace('"mocks"', '"mocks":"token", "mocks"', 1))
            with patch.object(m, "FIXTURES", folder/"fixtures"):
                with self.assertRaisesRegex(m.Denied, "DUPLICATE_JSON_FIELD"):
                    m.validate_fixtures()

    def test_no_hosted_cloud_dependencies_or_credentials(self):
        source = SRC.read_text()
        for bad in ("login.microsoftonline.com", "graph.microsoft.com",
                    "Authorization", "client_secret", "refresh_token",
                    "import subprocess", "import socket", "subprocess.run",
                    "shell=True", "eval(", "exec("):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, source)
        self.assertEqual(m.IMAGE_VERSION, "3.3.1")
        self.assertIn("@sha256:", m.IMAGE)

    def test_no_arbitrary_proxy(self):
        with self.assertRaisesRegex(m.Denied, "NONLOCAL_PROXY"):
            m.probe("http://evil.example:8000")


if __name__ == "__main__":
    unittest.main()
