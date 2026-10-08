import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "redact_winbot_fullrdte_diagnostic.py"
SPEC = importlib.util.spec_from_file_location("diag_redactor", SCRIPT)
redactor = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(redactor)


class FullRdteDiagnosticRedactorTests(unittest.TestCase):
    def _tar(self, path: Path) -> None:
        execution = {
            "assignment_id": "test-001",
            "exit_code": 34,
            "task_exit_code": 34,
            "timed_out": False,
            "capsule_sha256": "a" * 64,
            "worker_revision": "b" * 40,
            "run_id": "123",
            "run_attempt": "1",
            "result_budget": {"exceeded": False},
            "secret": "DO-NOT-LEAK",
        }
        full = {
            "schema_version": 2,
            "profile": "FullRDTE",
            "assignment_id": "test-001",
            "source_revision": "c" * 40,
            "projection_identity_sha256": "d" * 64,
            "classification": "ORACLE_FAILURE",
            "failure_domain": "readiness-a",
            "error_type": "RuntimeError",
            "error_message": "password Wb!" + "A" * 36 + " api_token=TOPSECRET",
            "elapsed_seconds": 12.5,
            "failure_context": {
                "command_name": "Get-Partition",
                "script_name": "build-master.ps1",
                "script_line": 317,
                "fully_qualified_error_id": "CimJob_BrokenCimSession",
                "category": "PermissionDenied",
                "reason": "CimException",
                "activity": "Get-Partition",
                "target_type": "Microsoft.Management.Infrastructure.CimInstance",
                "private_value": "DO-NOT-LEAK",
            },
            "build": {
                "projection_authorized": True,
                "master_build_started": True,
                "master_build_completed": False,
                "observed_switches": [{"name": "nat", "switch_type": "Internal"}],
                "network_placement_retryable": False,
                "private_value": "DO-NOT-LEAK",
            },
            "work_cells": {
                "a": {
                    "ready_seconds": 5,
                    "api_token_observed": True,
                    "api_token": "DO-NOT-LEAK",
                    "powershell_direct_observed": True,
                    "network_correction_attempted": True,
                    "network_correction_applied": True,
                    "network_correction_prefix_length": 20,
                    "network_correction_address": "DO-NOT-LEAK",
                    "network_correction_gateway": "DO-NOT-LEAK",
                    "provision_phase": "4/8-pkgs",
                    "provision_status": "progress",
                    "provision_elapsed": 321.0,
                },
                "b": {},
            },
            "persistence": {"b_drive_letter": "Q", "canary": "DO-NOT-LEAK"},
            "conformance": {"pytest_exit_code": 1, "raw": "DO-NOT-LEAK"},
            "cleanup": {"oracle_satisfied": True, "private": "DO-NOT-LEAK"},
            "materialization_receipt": {
                "complete": True,
                "cells": {
                    "a": {"disposed": True, "id": "DO-NOT-LEAK"},
                    "b": {"disposed": True, "runtime_disk": "DO-NOT-LEAK"},
                },
                "attachment": {"survived": True, "path": "DO-NOT-LEAK"},
                "runtime_seed": {"unchanged": True, "path": "DO-NOT-LEAK"},
            },
        }
        with tarfile.open(path, "w:gz") as tf:
            for name, obj in (("execution.json", execution), ("files/full-rdte.json", full)):
                raw=(json.dumps(obj)+"\n").encode()
                info=tarfile.TarInfo(name)
                info.size=len(raw)
                tf.addfile(info, io.BytesIO(raw))
            raw=(
                b"DO-NOT-LEAK stdout\n"
                b"[1/5] Checking prerequisites...\n"
                b"[2/5] Obtaining Windows ISO...\n"
                b"[3/5] Building provisioning VHD...\n"
                b"[4/5] Deploying Windows via DISM...\n"
                b"  Applying Windows image (engine: Wimlib)...\n"
                b"  Configuring boot loader...\n"
                b"  Staging WinBot guest files...\n"
            )
            info=tarfile.TarInfo("stdout.txt"); info.size=len(raw); tf.addfile(info,io.BytesIO(raw))
            raw=b"DO-NOT-LEAK stderr"
            info=tarfile.TarInfo("stderr.txt"); info.size=len(raw); tf.addfile(info,io.BytesIO(raw))

    def test_whitelist_and_redaction(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            tar=root/"result.tar.gz"
            out=root/"diagnostic.json"
            self._tar(tar)
            old_argv=list(__import__("sys").argv)
            try:
                __import__("sys").argv=["redactor","--result-tar",str(tar),"--output",str(out)]
                self.assertEqual(redactor.main(),0)
            finally:
                __import__("sys").argv=old_argv
            text=out.read_text()
            obj=json.loads(text)
            self.assertNotIn("DO-NOT-LEAK",text)
            self.assertNotIn("TOPSECRET",text)
            self.assertIn("<redacted-run-credential>",text)
            self.assertIn("observed_switches",obj["full_rdte"]["build"])
            self.assertTrue(obj["full_rdte"]["build"]["master_build_started"])
            self.assertFalse(obj["full_rdte"]["build"]["master_build_completed"])
            self.assertEqual(obj["full_rdte"]["failure_context"]["command_name"],"Get-Partition")
            self.assertEqual(obj["full_rdte"]["failure_context"]["script_name"],"build-master.ps1")
            self.assertEqual(obj["full_rdte"]["failure_context"]["script_line"],317)
            self.assertNotIn("private_value",obj["full_rdte"]["failure_context"])
            self.assertEqual(obj["full_rdte"]["persistence"]["b_drive_letter"],"Q")
            self.assertNotIn("api_token",obj["full_rdte"]["work_cells"]["a"])
            a=obj["full_rdte"]["work_cells"]["a"]
            self.assertTrue(a["powershell_direct_observed"])
            self.assertTrue(a["network_correction_attempted"])
            self.assertTrue(a["network_correction_applied"])
            self.assertEqual(a["network_correction_prefix_length"],20)
            self.assertEqual(a["provision_phase"],"4/8-pkgs")
            self.assertEqual(a["provision_status"],"progress")
            self.assertEqual(a["provision_elapsed"],321.0)
            self.assertNotIn("network_correction_address",a)
            self.assertNotIn("network_correction_gateway",a)
            self.assertNotIn("canary",obj["full_rdte"]["persistence"])
            receipt=obj["full_rdte"]["materialization_receipt"]
            self.assertTrue(receipt["complete"])
            self.assertTrue(receipt["cells"]["a"]["disposed"])
            self.assertTrue(receipt["cells"]["b"]["disposed"])
            self.assertTrue(receipt["attachment"]["survived"])
            self.assertTrue(receipt["runtime_seed"]["unchanged"])
            self.assertNotIn("id",receipt["cells"]["a"])
            self.assertNotIn("runtime_disk",receipt["cells"]["b"])
            self.assertNotIn("path",receipt["attachment"])
            self.assertNotIn("path",receipt["runtime_seed"])
            self.assertEqual(
                obj["progress"]["observed_build_stages"],
                ["prerequisites","source-media","provisioning-vhd","windows-deployment","image-apply","bootloader","guest-file-staging"],
            )
            self.assertEqual(obj["progress"]["last_build_stage"],"guest-file-staging")
            self.assertNotIn("DO-NOT-LEAK",json.dumps(obj["progress"]))


if __name__ == "__main__":
    unittest.main()
