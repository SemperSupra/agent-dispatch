import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_winbot_fullrdte_acceptance.py"
SOURCE = "1" * 40
PROJECTION = "2" * 64
CONTROL = "3" * 40
CAPSULE = "4" * 64


def good_reconstruction():
    return {
        "source_revision": SOURCE,
        "projection_identity_sha256": PROJECTION,
        "control_blob_sha": CONTROL,
        "capsule_sha256": CAPSULE,
        "private_repo_checkout": False,
        "staged_public_git_objects_only": True,
    }


def good_diagnostic():
    return {
        "scope": "redacted_fullrdte_diagnostic",
        "execution": {
            "capsule_sha256": CAPSULE,
            "task_exit_code": 0,
            "exit_code": 0,
            "timed_out": False,
            "result_budget": {"exceeded": False},
        },
        "full_rdte": {
            "profile": "FullRDTE",
            "source_revision": SOURCE,
            "projection_identity_sha256": PROJECTION,
            "classification": "SUPPORTED",
            "failure_domain": None,
            "error_type": None,
            "error_message": None,
            "build": {
                "projection_authorized": True,
                "master_build_started": True,
                "master_build_completed": True,
                "seed_test_vhd": True,
                "seed_integrity": True,
                "iso_reclaimed_before_materialization": True,
                "seed_unchanged": True,
                "seed_integrity_after": True,
            },
            "work_cells": {
                "a": {
                    "lineage": "True",
                    "ip_observed": True,
                    "api_token_observed": True,
                    "runtime_taint_written": True,
                    "vm_absent_after_dispose": True,
                    "runtime_disk_absent_after_dispose": True,
                },
                "b": {
                    "lineage": "True",
                    "prior_runtime_taint_absent": True,
                    "vm_absent_after_dispose": True,
                    "runtime_disk_absent_after_dispose": True,
                },
            },
            "persistence": {
                "explicit_attachment": True,
                "exists_before_a": True,
                "canary_written": True,
                "exists_after_a_dispose": True,
                "canary_survived_rematerialization": True,
                "exists_after_b_dispose": True,
                "oracle_satisfied": True,
            },
            "conformance": {
                "pytest_exit_code": 0,
                "results_present": True,
                "oracle_satisfied": True,
            },
            "cleanup": {
                "vm_a_absent": True,
                "vm_b_absent": True,
                "work_absent": True,
                "oracle_satisfied": True,
            },
        },
    }


class FullRdteAcceptanceVerifierTests(unittest.TestCase):
    def _run(self, diagnostic, reconstruction, *, control=CONTROL):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            diag_path = root / "diagnostic.json"
            recon_path = root / "reconstruction.json"
            diag_path.write_text(json.dumps(diagnostic), encoding="utf-8")
            recon_path.write_text(json.dumps(reconstruction), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--diagnostic", str(diag_path),
                    "--reconstruction", str(recon_path),
                    "--expected-source", SOURCE,
                    "--expected-projection", PROJECTION,
                    "--expected-control", control,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            return proc, json.loads(proc.stdout)

    def test_accepts_complete_exact_receipt(self):
        proc, result = self._run(good_diagnostic(), good_reconstruction())
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["failures"], [])

    def test_rejects_control_identity_mismatch(self):
        proc, result = self._run(good_diagnostic(), good_reconstruction(), control="9" * 40)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(result["accepted"])
        self.assertTrue(any("control_blob_sha" in x for x in result["failures"]))

    def test_rejects_nonzero_task_exit_even_if_fields_look_green(self):
        diag = good_diagnostic()
        diag["execution"]["task_exit_code"] = 47
        proc, result = self._run(diag, good_reconstruction())
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(any("task_exit_code" in x for x in result["failures"]))

    def test_rejects_cleanup_or_statelessness_failure(self):
        diag = good_diagnostic()
        diag["full_rdte"]["work_cells"]["b"]["prior_runtime_taint_absent"] = False
        diag["full_rdte"]["cleanup"]["oracle_satisfied"] = False
        proc, result = self._run(diag, good_reconstruction())
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(any("prior_runtime_taint_absent" in x for x in result["failures"]))
        self.assertTrue(any("cleanup.oracle_satisfied" in x for x in result["failures"]))


if __name__ == "__main__":
    unittest.main()
