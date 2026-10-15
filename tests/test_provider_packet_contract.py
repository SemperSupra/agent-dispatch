"""Public-safe, credential-free artifact packet security qualification."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "provider_packet_contract", ROOT / "scripts" / "provider_packet_contract.py")
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)
SOURCE = "a" * 40
PAYLOAD = b"synthetic-artifact-payload-v1\n"


def sample(**changes):
    doc = {"schema": "artifact-packet/v1", "artifact_id": "fixture-001",
           "source_sha": SOURCE, "data_class": "public-synthetic",
           "locator": "fixture://bucket-01/object-01", "revision": "rev-1",
           "sha256": hashlib.sha256(PAYLOAD).hexdigest(),
           "size_bytes": len(PAYLOAD)}
    doc.update(changes)
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


class PacketContractTests(unittest.TestCase):
    def test_deterministic_positive_receipt(self):
        a = m.verify(sample(), trusted_source_sha=SOURCE, observed_revision="rev-1", payload=PAYLOAD)
        b = m.verify(sample(), trusted_source_sha=SOURCE, observed_revision="rev-1", payload=PAYLOAD)
        self.assertEqual(a, b)
        self.assertTrue(a["fixture_verified"])
        self.assertFalse(a["provider_access_verified"])
        self.assertEqual(a["max_cost_usd"], 0)
        self.assertEqual(len(a["manifest_sha256"]), 64)

    def test_source_binding_not_self_attested(self):
        with self.assertRaisesRegex(m.Denied, "SOURCE_BINDING_DENIED"):
            m.verify(sample(), trusted_source_sha="b"*40, observed_revision="rev-1", payload=PAYLOAD)
        with self.assertRaisesRegex(m.Denied, "TRUSTED_SOURCE_INVALID"):
            m.parse(sample(), trusted_source_sha="unsafe")

    def test_data_class_and_unknown_fields(self):
        for changes in ({"data_class": "private"}, {"token": "secret"}, {"max_cost_usd": 10},
                        {"data_class": []}, {"data_class": None}):
            with self.subTest(changes=changes), self.assertRaises(m.Denied):
                m.parse(sample(**changes), trusted_source_sha=SOURCE)

    def test_locator_confinement(self):
        bad = ["onedrive://real-account/file", "fixture://bucket-01/../escape",
               "fixture://bucket-01/./object-01", "fixture://bucket-01/object-01?token=abc",
               "fixture://bucket-01/object-01/child", "https://example.org/private",
               "fixture://bucket-01/%2e%2e", "fixture://bucket-01\\object-01",
               "fixture://bucket-01/object-01#fragment"]
        for locator in bad:
            with self.subTest(locator=locator), self.assertRaisesRegex(m.Denied, "LOCATOR_DENIED"):
                m.parse(sample(locator=locator), trusted_source_sha=SOURCE)

    def test_duplicate_json_key_denied(self):
        raw = sample().replace(b'"size_bytes":', b'"size_bytes":1,"size_bytes":')
        with self.assertRaisesRegex(m.Denied, "DUPLICATE_FIELD"):
            m.parse(raw, trusted_source_sha=SOURCE)

    def test_revision_conflict_and_no_implicit_overwrite(self):
        with self.assertRaisesRegex(m.Denied, "REVISION_CONFLICT"):
            m.verify(sample(), trusted_source_sha=SOURCE, observed_revision="rev-2", payload=PAYLOAD)

    def test_hash_and_length_tamper(self):
        with self.assertRaisesRegex(m.Denied, "PAYLOAD_DIGEST_MISMATCH"):
            m.verify(sample(), trusted_source_sha=SOURCE, observed_revision="rev-1", payload=b"S"+PAYLOAD[1:])
        with self.assertRaisesRegex(m.Denied, "PAYLOAD_LENGTH_MISMATCH"):
            m.verify(sample(), trusted_source_sha=SOURCE, observed_revision="rev-1", payload=PAYLOAD+b"!")

    def test_malformed_and_oversized(self):
        for raw in (b"not-json", b"{"+b" "*4096+b"}", b"\xff"*32, b"[]"):
            with self.subTest(raw=raw[:20]), self.assertRaises(m.Denied):
                m.parse(raw, trusted_source_sha=SOURCE)

    def test_bool_size_or_nan_denied(self):
        with self.assertRaisesRegex(m.Denied, "PAYLOAD_BOUNDS"):
            m.parse(sample(size_bytes=True), trusted_source_sha=SOURCE)
        with self.assertRaisesRegex(m.Denied, "INVALID_NUMBER"):
            m.parse(sample().replace(b'"size_bytes":', b'"size_bytes":NaN,"unused_size":'),
                    trusted_source_sha=SOURCE)

    def test_revision_format_denied(self):
        for rev in ("../../", "", "rev-\u001e", "abc", "rev-A", "rev-"+"0"*33):
            with self.subTest(rev=rev), self.assertRaisesRegex(m.Denied, "REVISION_DENIED"):
                m.parse(sample(revision=rev), trusted_source_sha=SOURCE)

    def test_no_provider_or_command_execution(self):
        src = (ROOT / "scripts" / "provider_packet_contract.py").read_text()
        for denied in ("import subprocess", "import requests", "import urllib",
                       "import socket", "shell=True", "eval(", "exec(",
                       "os.environ", "open("):
            self.assertNotIn(denied, src)


if __name__ == "__main__":
    unittest.main()
