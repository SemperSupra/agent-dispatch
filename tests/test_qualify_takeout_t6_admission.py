"""No-actuation Takeout guest-admission negative/positive-static contract."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/qualify_takeout_t6_admission.py"
spec = importlib.util.spec_from_file_location("preflight", SCRIPT)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
CANDIDATE = Path(__file__).resolve().parents[1] / "config/takeout-t6-admission-candidate.json"
C = json.loads(CANDIDATE.read_text())
BASE = {"schema": "truenas-capsule-providers/v1", "providers": []}
MC = {"schema": "gha-kvm-truenas-run-request/v1",
      "product": "minecraft-vanilla-263", "request_id": "minecraft-unique"}
WORKFLOW = 'schema="gha-kvm-truenas-run-request/v1"; truenas_t6_product="minecraft-vanilla-263"'


def classify(candidate=None, registry=None, request=None, workflow=WORKFLOW,
             probe=False, artifact=False):
    return v.check(copy.deepcopy(C if candidate is None else candidate),
                   copy.deepcopy(BASE if registry is None else registry),
                   copy.deepcopy(MC if request is None else request),
                   workflow, probe_path_present=probe,
                   control_artifact_present=artifact)


class Tests(unittest.TestCase):
    def test_missing_real_provider_is_hold(self):
        res = classify()
        self.assertEqual(res["status"], "BLOCKED")
        self.assertIn("PRODUCT_PROVIDER_NOT_BOUND", res["blockers"])
        self.assertIn("WORKFLOW_SELECTOR_NOT_BOUND", res["blockers"])
        self.assertIn("FRESH_TAKEOUT_RUN_REQUEST_MISSING", res["blockers"])
        self.assertFalse(res["guest_started"])
        self.assertFalse(res["docker_read_required"])

    def test_existing_other_product_provider_does_not_admit(self):
        provider = {"schema": "truenas-capsule-providers/v1", "providers": [
            {"id": "minecraft-paper-t6", "existing_selector": "minecraft-paper",
             "probe": "scripts/truenas_middleware_minecraft_t6_probe.py",
             "control_artifact": "minecraft-paper-truenas-t6-control"}]}
        self.assertIn("PRODUCT_PROVIDER_NOT_BOUND", classify(registry=provider)["blockers"])

    def test_provider_name_without_correct_selector_does_not_admit(self):
        p = {"id": "takeout-synthetic-t6", "existing_selector": "minecraft-paper",
             "probe": "scripts/truenas_middleware_takeout_t6_probe.py",
             "control_artifact": "takeout-synthetic-t6-control"}
        self.assertIn("PRODUCT_PROVIDER_NOT_BOUND", classify(
            registry={"schema": "truenas-capsule-providers/v1", "providers": [p]})["blockers"])

    def test_claimed_native_success_cannot_change_hold(self):
        c = copy.deepcopy(C)
        c["decision"] = "READY"
        with self.assertRaisesRegex(v.AdmissionError, "CANDIDATE_MUTATED_PAST_HOLD"):
            classify(candidate=c)

    def test_privileged_scope_forbidden(self):
        for key in ("allow_global_docker_socket", "allow_new_site_docker_read",
                    "allow_real_google_data", "allow_physical_truenas",
                    "allow_private_gha_minutes"):
            with self.subTest(key=key):
                c = copy.deepcopy(C)
                c["constraints"][key] = True
                with self.assertRaisesRegex(v.AdmissionError, "PRIVILEGE_OR_BUDGET_DRIFT"):
                    classify(candidate=c)

    def test_report_requires_independent_validation(self):
        c = copy.deepcopy(C)
        c["completion"]["application_self_report_is_sufficient"] = True
        with self.assertRaisesRegex(v.AdmissionError, "COMPLETION_CONTRACT_DRIFT"):
            classify(candidate=c)

    def test_no_numeric_exit_or_docker_read_mandatory(self):
        for key in ("process_exit_required", "docker_read_required"):
            c = copy.deepcopy(C)
            c["completion"][key] = True
            with self.assertRaisesRegex(v.AdmissionError, "COMPLETION_CONTRACT_DRIFT"):
                classify(candidate=c)

    def test_untrusted_mutation_of_product_id_rejected(self):
        c = copy.deepcopy(C)
        c["execution"]["selector"] = "official-catalog"
        with self.assertRaisesRegex(v.AdmissionError, "EXECUTION_PROPOSAL_DRIFT"):
            classify(candidate=c)

    def test_even_all_static_facts_do_not_dispatch(self):
        p = {"id": "takeout-synthetic-t6", "existing_selector": "takeout-synthetic",
             "probe": "scripts/truenas_middleware_takeout_t6_probe.py",
             "control_artifact": "takeout-synthetic-t6-control"}
        c = copy.deepcopy(C)
        c["consumer"].update({"data_outcome_observer": "CI_QUALIFIED",
                              "native_app_observation": "ACCEPTED",
                              "zfs_retention": "ACCEPTED"})
        c["execution"]["fresh_takeout_run_request"] = "tn-unique-takeout-001"
        c["execution"]["exclusive_lane_release"] = "authority:approved"
        r = classify(candidate=c,
                     registry={"schema": "truenas-capsule-providers/v1", "providers": [p]},
                     request={"schema": "gha-kvm-truenas-run-request/v1",
                              "product": "takeout-synthetic", "request_id": "tn-unique-takeout-001"},
                     workflow=WORKFLOW + ' "takeout-synthetic"', probe=True, artifact=True)
        self.assertEqual(r["status"], "EXTERNAL_ADMISSION_STILL_REQUIRED")
        self.assertFalse(r["already_dispatched"])
        self.assertFalse(r["guest_started"])

    def test_expired_image_is_blocked(self):
        c = copy.deepcopy(C)
        c["producer"]["oci_artifact_expires"] = "EXPIRED"
        self.assertIn("OCI_ARTIFACT_EXPIRED", classify(candidate=c)["blockers"])

    def test_unqualified_foundry_observer_blocks(self):
        self.assertIn("FOUNDRY_DATA_OUTCOME_OBSERVER_NOT_QUALIFIED",
                      classify()["blockers"])
        self.assertIn("NATIVE_ZFS_RETENTION_NOT_QUALIFIED", classify()["blockers"])

    def test_absent_probe_control_blocks(self):
        r = classify(probe=False, artifact=False)
        self.assertIn("NATIVE_TAKEOUT_PROBE_NOT_QUALIFIED", r["blockers"])
        self.assertIn("GUEST_CONTROL_ARTIFACT_NOT_QUALIFIED", r["blockers"])

    def test_wrong_middleware_version_refused(self):
        c = copy.deepcopy(C)
        c["target"]["middleware_commit"] = "0"*40
        with self.assertRaisesRegex(v.AdmissionError, "TARGET_DRIFT"):
            classify(candidate=c)


if __name__ == "__main__":
    unittest.main()
