#!/usr/bin/env python3
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import truenas_existing_probe_capsule_executor as exe
from truenas_session_manifest import SessionError


class ExistingProbeExecutorTests(unittest.TestCase):
    def temp_root(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return pathlib.Path(td.name)

    def fixture(self, provider_id):
        root = self.temp_root()
        probe = root / "probe.py"
        probe.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        password = root / "password"
        password.write_text("test\n", encoding="utf-8")
        control = root / "control"
        control.mkdir()
        ports = {
            "litellm-t6": {"service": 18100},
            "wow-sidecar-t6": {},
            "garm-t6": {"service": 18101},
            "official-catalog-t6": {},
            "foliorelay-t6": {"control": 18102, "ipp": 18103, "observer": 18104},
        }[provider_id]
        descriptor = {
            "schema": "truenas-capsule-dispatch/v1",
            "manifest_sha256": "a" * 64,
            "capsule": {
                "id": "capsule-one",
                "provider": provider_id,
                "mutating": True,
                "cleanup_required": True,
            },
            "provider": {
                "id": provider_id,
                "probe": str(probe),
            },
        }
        context = {
            "schema": "truenas-capsule-context/v1",
            "host": "127.0.0.1",
            "middleware_port": 18000,
            "password_file": str(password),
            "tls": True,
            "providers": {
                provider_id: {
                    "control_dir": str(control),
                    "foundry_commit": "1" * 40,
                    "ports": ports,
                }
            },
        }
        return root, descriptor, context

    def test_existing_provider_commands_preserve_current_probe_arguments(self):
        expected = {
            "litellm-t6": ["--service-port", "18100", "--state-timeout", "240"],
            "wow-sidecar-t6": ["--state-timeout", "240"],
            "garm-t6": ["--service-port", "18101", "--state-timeout", "240"],
            "official-catalog-t6": ["--state-timeout", "240"],
            "foliorelay-t6": [
                "--control-port", "18102",
                "--ipp-port", "18103",
                "--observer-port", "18104",
                "--state-timeout", "300",
            ],
        }
        for provider_id, required in expected.items():
            with self.subTest(provider=provider_id):
                root, descriptor, context = self.fixture(provider_id)
                command = exe.build_probe_command(
                    descriptor, context, root / "provider-receipt.json"
                )
                self.assertEqual(command[0], sys.executable)
                self.assertIn("--host", command)
                self.assertIn("127.0.0.1", command)
                self.assertIn("--port", command)
                self.assertIn("18000", command)
                self.assertIn("--tls", command)
                self.assertIn("--password-file", command)
                self.assertIn("--control-dir", command)
                self.assertIn("--foundry-commit", command)
                for token in required:
                    self.assertIn(token, command)

    def test_supported_provider_receipt_maps_to_clean_supported_capsule(self):
        _, descriptor, _ = self.fixture("foliorelay-t6")
        receipt = exe.wrap_receipt(
            descriptor,
            {
                "classification": "SUPPORTED",
                "oracleSatisfied": True,
                "detail": "passed",
            },
            0,
            "",
        )
        self.assertEqual(receipt["verdict"], "SUPPORTED")
        self.assertTrue(receipt["cleanup_satisfied"])
        self.assertTrue(receipt["platform_healthy"])
        self.assertTrue(receipt["authority_satisfied"])
        self.assertTrue(receipt["resource_guardrail_satisfied"])

    def test_failed_provider_receipt_stops_fail_closed_until_membrane_exists(self):
        _, descriptor, _ = self.fixture("foliorelay-t6")
        receipt = exe.wrap_receipt(
            descriptor,
            {
                "classification": "ORACLE_FAILURE",
                "oracleSatisfied": False,
                "detail": "product oracle failed",
            },
            0,
            "",
        )
        self.assertEqual(receipt["verdict"], "ORACLE_FAILURE")
        self.assertFalse(receipt["cleanup_satisfied"])
        self.assertFalse(receipt["platform_healthy"])

    def test_missing_provider_receipt_is_harness_failure(self):
        _, descriptor, _ = self.fixture("official-catalog-t6")
        receipt = exe.wrap_receipt(descriptor, None, 7, "crashed")
        self.assertEqual(receipt["verdict"], "HARNESS_FAILURE")
        self.assertFalse(receipt["cleanup_satisfied"])
        self.assertFalse(receipt["platform_healthy"])
        self.assertIn("crashed", receipt["reason"])

    def test_context_requires_exact_provider_binding(self):
        root, descriptor, context = self.fixture("garm-t6")
        context["providers"] = {}
        with self.assertRaisesRegex(SessionError, "no provider binding"):
            exe.build_probe_command(descriptor, context, root / "receipt.json")


if __name__ == "__main__":
    unittest.main()
