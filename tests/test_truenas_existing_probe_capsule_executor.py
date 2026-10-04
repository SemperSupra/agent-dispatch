#!/usr/bin/env python3
import json
import pathlib
import sys
import stat
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import truenas_existing_probe_capsule_executor as exe
import truenas_session_manifest as manifest_mod
import truenas_session_runner as session_runner
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

    def test_session_runner_executes_one_existing_probe_capsule_end_to_end(self):
        root = self.temp_root()
        probe = root / "fake_probe.py"
        probe.write_text(
            """#!/usr/bin/env python3
import argparse, json, pathlib
p=argparse.ArgumentParser()
p.add_argument("--out", required=True)
p.add_argument("--host"); p.add_argument("--port"); p.add_argument("--password-file")
p.add_argument("--control-dir"); p.add_argument("--foundry-commit")
p.add_argument("--control-port"); p.add_argument("--ipp-port"); p.add_argument("--observer-port")
p.add_argument("--timeout"); p.add_argument("--job-timeout"); p.add_argument("--state-timeout")
p.add_argument("--tls", action="store_true")
a=p.parse_args()
pathlib.Path(a.out).write_text(json.dumps({
  "classification":"SUPPORTED",
  "oracleSatisfied":True,
  "detail":"synthetic accepted existing-probe receipt"
})+"\\n")
""",
            encoding="utf-8",
        )
        password = root / "password"
        password.write_text("test\n", encoding="utf-8")
        control = root / "control"
        control.mkdir()

        targets = root / "targets.json"
        targets.write_text(json.dumps({
            "schema":"gha-kvm-truenas-targets/v1",
            "targets":[{"version":"26.0.0-BETA.3"}],
        })+"\n", encoding="utf-8")

        providers = root / "providers.json"
        providers.write_text(json.dumps({
            "schema":"truenas-capsule-providers/v1",
            "providers":[{
                "id":"foliorelay-t6",
                "kind":"foundry-product",
                "product":"foliorelay",
                "probe":str(probe),
                "control_artifact":"foliorelay-t6-beta3-control",
                "existing_selector":"foliorelay",
            }],
        })+"\n", encoding="utf-8")

        capsule = {
            "schema":"truenas-capsule/v1",
            "id":"foliorelay-one",
            "kind":"foundry-product",
            "provider":"foliorelay-t6",
            "authority":{"repository":"SemperSupra/folio-relay","issue":29},
            "exact":{"source_ref":"1"*40},
            "namespace":"rdte-foliorelay-one",
            "ports":[18102,18103,18104],
            "requirements":["apps","zfs-pool"],
            "resources":{"memory_mib":1024,"download_mib":64,"estimated_minutes":2},
            "phases":{"setup":True,"apply":True,"verify":True,"cleanup":True},
            "oracle":"existing FolioRelay T6 oracle",
            "receipt_contract":"truenas-capsule-execution/v1",
            "retry_policy":"read-only-reconcile",
            "mutating":True,
            "cleanup_required":True,
            "dependencies":[],
        }
        manifest = {
            "schema":"truenas-session/v1",
            "session_id":"tn-26-beta3-single-equivalence-001",
            "version":"26.0.0-BETA.3",
            "authority":{"repository":"SemperSupra/agent-dispatch-private","issue":480},
            "budget":{"guest_memory_mib":8192,"download_mib":128,"timeout_minutes":10},
            "pool":{"name":"rdtepool","data_disks":2},
            "capsules":[capsule],
        }
        manifest["manifest_sha256"] = manifest_mod.manifest_digest(manifest)
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest)+"\n", encoding="utf-8")

        context = root / "context.json"
        context.write_text(json.dumps({
            "schema":"truenas-capsule-context/v1",
            "host":"127.0.0.1",
            "middleware_port":18000,
            "password_file":str(password),
            "tls":False,
            "providers":{
                "foliorelay-t6":{
                    "control_dir":str(control),
                    "foundry_commit":"1"*40,
                    "ports":{"control":18102,"ipp":18103,"observer":18104},
                }
            },
        })+"\n", encoding="utf-8")

        wrapper = root / "executor"
        executor_script = ROOT / "scripts" / "truenas_existing_probe_capsule_executor.py"
        wrapper.write_text(
            f"#!/bin/sh\nexec {sys.executable} {executor_script} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)

        result = session_runner.run_session(
            manifest_path,
            targets,
            providers,
            wrapper,
            context,
            root / "receipts",
        )
        self.assertEqual(result["classification"], "SESSION_CLEAN")
        self.assertTrue(result["session_clean"])
        self.assertFalse(result["product_acceptance_inferred"])
        self.assertEqual(len(result["capsules"]), 1)
        self.assertEqual(result["capsules"][0]["verdict"], "SUPPORTED")
        self.assertTrue(result["capsules"][0]["cleanup_satisfied"])
        self.assertTrue(result["capsules"][0]["platform_healthy"])

    def test_context_requires_exact_provider_binding(self):
        root, descriptor, context = self.fixture("garm-t6")
        context["providers"] = {}
        with self.assertRaisesRegex(SessionError, "no provider binding"):
            exe.build_probe_command(descriptor, context, root / "receipt.json")


if __name__ == "__main__":
    unittest.main()
