"""CPU public-safe typed request acceptance and adversarial negative controls."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "scripts" / "gha_workload_request.py"
spec = importlib.util.spec_from_file_location("gha_workload_request", SRC)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
X64 = "requests/gha/cpu-x64-arithmetic-v1.json"
ARM = "requests/gha/cpu-arm64-contract-v1.json"


class TypedWorkRequestTests(unittest.TestCase):
    def test_existing_two_shapes_are_admitted(self):
        first, second = m.plan(X64), m.plan(ARM)
        self.assertEqual(first["runner"], "ubuntu-24.04")
        self.assertEqual(second["runner"], "ubuntu-24.04-arm")
        self.assertEqual(first["max_cost_usd"], second["max_cost_usd"])
        self.assertEqual(first["max_cost_usd"], 0)
        self.assertEqual(first["max_attempts"], 1)
        self.assertEqual(first, m.plan(X64))
        self.assertEqual(len(first["request_sha256"]), 64)

    def test_mail_synthetic_profile_and_native_negative_oracle(self):
        plan = m.plan("requests/gha/mail-synthetic-baseline-v1.json")
        self.assertEqual(plan["runner"], "ubuntu-24.04")
        self.assertEqual(plan["workload"], "mail-synthetic-baseline")
        self.assertEqual(plan["max_cost_usd"], 0)
        self.assertEqual(plan["max_attempts"], 1)
        verdict = m._execute("mail-synthetic-baseline", 90)
        self.assertTrue(verdict["oracle_verified"], verdict)
        self.assertEqual(verdict["classification"], "PASS")
        self.assertTrue(verdict["retrieval_only"])
        self.assertFalse(verdict["model_inference"])
        self.assertEqual(verdict["query_count"], 9)
        self.assertEqual(len(verdict["fixture_sha256"]), 64)

    def test_offline_policy_candidate_search_requires_heldout_and_negative_gates(self):
        import subprocess
        cp = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_mail_policy_optimization.py"],
            cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False)
        self.assertEqual(cp.returncode, 0, cp.stderr.decode("utf-8", "replace"))
        sys.path.insert(0, str(ROOT / "scripts"))
        import mail_policy_optimization as optimizer
        observed = optimizer.select_and_evaluate()
        self.assertEqual(observed["selected_policy"], "multilingual-prefix")
        self.assertEqual(observed["holdout_baseline_hits"], 0)
        self.assertEqual(observed["holdout_selected_hits"], 3)
        self.assertFalse(observed["model_inference"])
        self.assertFalse(observed["promoted_to_runtime"])

    def test_openworker_upstream_fixed_workload_and_source_admission(self):
        request = m.plan("requests/gha/mail-openworker-policy-v1.json")
        self.assertEqual(request["runner"], "ubuntu-24.04")
        self.assertEqual(request["workload"], "mail-openworker-policy")
        self.assertEqual(request["max_attempts"], 1)
        self.assertEqual(request["max_cost_usd"], 0)
        import subprocess
        cp = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_qualify_openworker_readonly.py"],
            cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False)
        self.assertEqual(cp.returncode, 0, cp.stderr.decode("utf-8", "replace"))

    def test_ragmail_loss_witness_uses_reviewed_public_source_and_offline_negatives(self):
        plan = m.plan("requests/gha/mail-ragmail-loss-v1.json")
        self.assertEqual(plan["workload"], "mail-ragmail-loss-witness")
        self.assertEqual(plan["runner"], "ubuntu-24.04")
        self.assertEqual(plan["max_cost_usd"], 0)
        self.assertEqual(plan["max_attempts"], 1)
        import subprocess
        cp = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_qualify_ragmail_mbox_loss.py"],
            cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        self.assertEqual(cp.returncode, 0, cp.stderr.decode("utf-8", "replace"))

    def test_go_evidence_challenge_fixed_zero_cost_profile(self):
        plan = m.plan("requests/gha/mail-evidence-go-v1.json")
        self.assertEqual(plan["workload"], "mail-evidence-go-challenge")
        self.assertEqual(plan["runner"], "ubuntu-24.04")
        self.assertEqual(plan["max_cost_usd"], 0)
        self.assertEqual(plan["max_attempts"], 1)

    def test_original_openworker_headless_fake_email_source_admitted_only(self):
        plan = m.plan("requests/gha/mail-openworker-headless-v1.json")
        self.assertEqual(plan["workload"], "mail-openworker-headless-mail")
        self.assertEqual(plan["runner"], "ubuntu-24.04")
        self.assertEqual(plan["max_cost_usd"], 0)
        self.assertEqual(plan["max_attempts"], 1)
        import subprocess
        cp = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_qualify_openworker_headless_mail.py"],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False)
        self.assertEqual(cp.returncode, 0, cp.stderr.decode("utf-8", "replace"))

    def test_full_original_openworker_scripted_v1_plan_is_zero_cost(self):
        plan = m.plan("requests/gha/mail-openworker-scripted-v1.json")
        self.assertEqual(plan["workload"], "mail-openworker-scripted")
        self.assertEqual(plan["runner"], "ubuntu-24.04")
        self.assertEqual(plan["max_cost_usd"], 0)
        self.assertEqual(plan["max_attempts"], 1)
        self.assertLessEqual(plan["timeout_seconds"], 240)

    def test_full_openworker_offline_source_and_secrets_negatives(self):
        import subprocess
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_qualify_openworker_scripted_runtime.py"],
            cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=25, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", "replace"))

    def test_public_cpu_pr_matrix_keeps_expensive_network_upstream_probes_on_demand(self):
        workflow = (ROOT / ".github" / "workflows" / "gha-typed-public-cpu.yml").read_text(
            encoding="utf-8")
        self.assertIn("  cpu-native-proofs:", workflow)
        native = workflow.split("  cpu-native-proofs:", 1)[1].split("\n  plan:", 1)[0]
        required = (
            "requests/gha/cpu-x64-arithmetic-v1.json",
            "requests/gha/cpu-arm64-contract-v1.json",
            "requests/gha/mail-synthetic-baseline-v1.json",
            "requests/gha/mail-evidence-go-v1.json",
        )
        for request in required:
            self.assertIn("request: " + request, native)
            self.assertEqual(native.count("request: " + request), 1)
        on_demand = (
            ("mail-openworker-policy-v1", "mail-openworker-policy"),
            ("mail-ragmail-loss-v1", "mail-ragmail-loss-witness"),
            ("mail-openworker-headless-v1", "mail-openworker-headless-mail"),
            ("mail-openworker-scripted-v1", "mail-openworker-scripted"),
        )
        for name, workload in on_demand:
            with self.subTest(profile=name):
                self.assertNotIn("request: requests/gha/" + name + ".json", native)
                plan = m.plan("requests/gha/" + name + ".json")
                self.assertEqual(plan["workload"], workload)
                self.assertEqual(plan["max_cost_usd"], 0)
                self.assertEqual(plan["max_attempts"], 1)

    def test_original_prolog_fixed_public_synthetic_profile_and_source(self):
        planned=m.plan("requests/gha/mail-temporal-swipl-r2.json")
        self.assertEqual(planned["workload"],"mail-temporal-swipl-r2")
        self.assertEqual(planned["runner"],"ubuntu-24.04")
        self.assertEqual(planned["max_cost_usd"],0)
        self.assertEqual(planned["max_attempts"],1)
        self.assertLessEqual(planned["timeout_seconds"],180)
        source=(ROOT/"tools/mail-evidence-challenge/temporal_prolog/qualify.pl").read_text()
        for must in ("source(", "claim(", "rule_proof(","run_tests(","begin_tests("):
            self.assertIn(must,source)
        self.assertNotIn("shell(",source)
        self.assertNotIn("process_create(",source)

    def test_original_prolog_uses_on_demand_install_not_default_cpu_matrix(self):
        text=(ROOT/".github/workflows/gha-typed-public-cpu.yml").read_text()
        routine=text.split("  cpu-native-proofs:",1)[1].split("\n  plan:",1)[0]
        self.assertNotIn("requests/gha/mail-temporal-swipl-r2.json",routine)
        admitted=text.split("\n  execute:",1)[1]
        self.assertIn("if: inputs.request == 'requests/gha/mail-temporal-swipl-r2.json'",admitted)
        self.assertIn("sudo apt-get install -y -qq --no-install-recommends swi-prolog-nox",admitted)

    def test_native_postgres18_profile_and_offline_source_guard(self):
        plan=m.plan("requests/gha/mail-temporal-postgres-r2.json")
        self.assertEqual(plan["workload"],"mail-temporal-postgres-r2")
        self.assertEqual(plan["runner"],"ubuntu-24.04")
        self.assertLessEqual(plan["timeout_seconds"],240)
        self.assertEqual(plan["max_attempts"],1)
        self.assertEqual(plan["max_cost_usd"],0)
        import subprocess
        cp=subprocess.run(
            [sys.executable,"-m","unittest","discover","-s","tests",
             "-p","test_qualify_temporal_postgres18.py"],
            cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=25,check=False)
        self.assertEqual(cp.returncode,0,cp.stderr.decode("utf-8","replace"))

    def test_postgres_research_remains_on_demand_not_every_pr(self):
        workflow=(ROOT/".github"/"workflows"/"gha-typed-public-cpu.yml").read_text()
        normal=workflow.split("  cpu-native-proofs:",1)[1].split("\n  plan:",1)[0]
        self.assertNotIn("requests/gha/mail-temporal-postgres-r2.json",normal)
        self.assertIn("  execute:",workflow)
        req=m.plan("requests/gha/mail-temporal-postgres-r2.json")
        self.assertEqual(req["max_cost_usd"],0)
        self.assertEqual(req["max_attempts"],1)

    def test_temporal_postgres_has_single_digest_pinned_typed_authority(self):
        request = m.plan("requests/gha/mail-temporal-postgres-r2.json")
        self.assertEqual(request["workload"], "mail-temporal-postgres-r2")
        self.assertEqual(request["max_attempts"], 1)
        self.assertEqual(request["max_cost_usd"], 0)
        workflow = (ROOT / ".github" / "workflows" /
                    "gha-typed-public-cpu.yml").read_text(encoding="utf-8")
        self.assertIn("temporal-swi-prolog-native:", workflow)
        self.assertNotIn("temporal-postgres18-native:", workflow)
        self.assertNotIn("scripts/qualify_postgres18_temporal.py", workflow)
        self.assertTrue((ROOT/"scripts"/"qualify_temporal_postgres18.py").is_file())
        self.assertFalse((ROOT/"scripts"/"qualify_postgres18_temporal.py").exists())
        self.assertFalse((ROOT/"scripts"/"verify_postgres18_temporal.py").exists())
        pinned = (ROOT/"scripts"/"qualify_temporal_postgres18.py").read_text(
            encoding="utf-8")
        self.assertIn("postgres:18.7-trixie@sha256:", pinned)
        self.assertIn("FROM source_occurrence", pinned)

    def test_no_unreviewed_paths_or_urls(self):
        for bad in ("../secrets.env", "requests/gha/../private.json",
                    "/tmp/public.json", "http://example.test/run.json",
                    "requests/gha/test.yml", "requests/gha/n.json",
                    "requests/gha/a;echo-b.json"):
            with self.subTest(path=bad), self.assertRaises(m.Denied):
                m.plan(bad)

    def test_request_mutations_denied(self):
        source, _ = m.read_request(X64)
        examples = [
            {"runner":"windows-11-arm"},
            {"runner":[]},
            {"workload":"run-shell"},
            {"workload":{}},
            {"execute":"curl attacker.test"},
            {"max_cost_usd":1},
            {"max_attempts":2},
            {"max_attempts":True},
            {"timeout_seconds":241},
            {"timeout_seconds":True},
            {"data_class":"private-holdout"},
            {"assignment_id":"../private"},
            {"schema":"unknown/v0"},
        ]
        for mutation in examples:
            with self.subTest(value=mutation), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                dest = root/"requests"/"gha"
                dest.mkdir(parents=True)
                data=dict(source)
                data.update(mutation)
                (dest/"cpu-test.json").write_text(json.dumps(data),encoding="utf-8")
                with patch.object(m,"ROOT",root), patch.object(m,"REQUEST_DIR",dest):
                    with self.assertRaises(m.Denied):
                        m.plan("requests/gha/cpu-test.json")

    def test_digest_bind_rejects_drift(self):
        result = m.plan(X64)
        with self.assertRaisesRegex(m.Denied,"REQUEST_DIGEST_CHANGED"):
            m.run(X64, "0"*64)
        with self.assertRaisesRegex(m.Denied,"REQUEST_DIGEST_CHANGED"):
            m.run(X64, "hello")
        self.assertEqual(result["request_sha256"], m.plan(X64)["request_sha256"])

    def test_shape_absence_is_not_capability_pass(self):
        first=m.plan(X64)
        with patch.object(m.platform,"system",return_value="Linux"), \
             patch.object(m.platform,"machine",return_value="x86_64"), \
             patch.dict(m.os.environ,{"RUNNER_ARCH":"ARM64"}):
            receipt=m.run(X64, first["request_sha256"])
        self.assertFalse(receipt["qualified"])
        self.assertEqual(receipt["result"]["classification"],"FAIL_RUNNER_SHAPE")
        self.assertFalse(receipt["shape_verified"])

    def test_arithmetic_oracle_matched(self):
        d=m._execute("arithmetic-oracle",30)
        self.assertTrue(d["oracle_verified"])
        self.assertEqual(d["classification"],"PASS")
        self.assertEqual(d["task_count"],256)
        self.assertEqual(len(d["fixture_sha256"]),64)

    def test_non_shell_backend(self):
        source=SRC.read_text()
        self.assertNotIn("shell=True",source)
        self.assertNotIn("eval(",source)
        self.assertNotIn("exec(",source)
        self.assertIn('"arithmetic-oracle"',source)
        self.assertIn('"sealed-contract-native"',source)

    def test_symlink_source_is_not_admitted(self):
        source, _ = m.read_request(X64)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            dest=root/"requests"/"gha"
            dest.mkdir(parents=True)
            outside=root/"unreviewed.json"
            outside.write_text(json.dumps(source))
            (dest/"cpu-test.json").symlink_to(outside)
            with patch.object(m,"ROOT",root), patch.object(m,"REQUEST_DIR",dest):
                with self.assertRaisesRegex(m.Denied,"REQUEST_NOT_REVIEWED_LOCAL_FILE"):
                    m.plan("requests/gha/cpu-test.json")



# V2 assignment profile separation: tested against the same reviewed on-disk
# profiles, with zero GitHub credentials, Sidecar authority, or runner budget.
spec2 = importlib.util.spec_from_file_location(
    "gha_assignment_contract", ROOT / "scripts" / "gha_assignment_contract.py")
a = importlib.util.module_from_spec(spec2)
sys.modules[spec2.name] = a
spec2.loader.exec_module(a)
from datetime import datetime, timezone, timedelta

NOW = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
SOURCE = "a" * 40


def sample(profile_id="cpu-x64-arithmetic-v1"):
    p = m.plan(a.PROFILES[profile_id])
    return {
        "schema": "gha-typed-assignment/v1",
        "assignment_id": "test-delegated-cpu-001",
        "nonce": "1" * 32,
        "profile_id": profile_id,
        "profile_sha256": p["request_sha256"],
        "source_sha": SOURCE,
        "authority_sha256": "b" * 64,
        "issued_at": "2026-10-14T15:59:00Z",
        "expires_at": "2026-10-14T16:09:00Z",
        "data_class": "public-synthetic",
        "max_attempts": 1,
        "max_cost_usd": 0,
    }


def admit_sample(data, **kwargs):
    return a.admit(json.dumps(data), trusted_source_sha=SOURCE, now=NOW, **kwargs)


class DynamicAssignmentContractTests(unittest.TestCase):
    def test_both_reviewed_profiles_and_canonical_identity(self):
        for profile_id, runner in (("cpu-x64-arithmetic-v1", "ubuntu-24.04"),
                                   ("cpu-arm64-contract-v1", "ubuntu-24.04-arm")):
            with self.subTest(profile=profile_id):
                doc = sample(profile_id)
                accepted = admit_sample(doc)
                self.assertEqual(accepted["runner"], runner)
                self.assertEqual(accepted["data_class"], "public-synthetic")
                self.assertEqual(accepted["max_attempts"], 1)
                self.assertEqual(accepted["max_cost_usd"], 0)
                other = a.admit(json.dumps(doc, indent=2), trusted_source_sha=SOURCE, now=NOW)
                self.assertEqual(accepted["assignment_sha256"], other["assignment_sha256"])

    def test_extra_fields_and_privilege_smuggling_denied(self):
        for field, val in (("command", "echo secret"), ("script", "curl example.org"),
                           ("runner", "self-hosted"), ("workflow", "other.yml"),
                           ("url", "https://example.org"), ("secret", "credential"),
                           ("scope", "admin"), ("ref", "feature-branch")):
            with self.subTest(field=field):
                doc = sample()
                doc[field] = val
                with self.assertRaisesRegex(a.Denied, "ASSIGNMENT_FIELDS_DENIED"):
                    admit_sample(doc)

    def test_wrong_id_profile_digest_and_privacy_denied(self):
        cases = [
            ({"assignment_id": "../escape"}, "ASSIGNMENT_ID_DENIED"),
            ({"nonce": "x"*32}, "ASSIGNMENT_NONCE_DENIED"),
            ({"profile_id": "cpu-win-shell"}, "PROFILE_ID_DENIED"),
            ({"profile_id": []}, "PROFILE_ID_DENIED"),
            ({"profile_id": {}}, "PROFILE_ID_DENIED"),
            ({"profile_sha256": "f"*64}, "PROFILE_DIGEST_DRIFT"),
            ({"source_sha": "c"*40}, "SOURCE_DRIFT"),
            ({"data_class": "private"}, "PRIVATE_DATA_DENIED"),
            ({"max_attempts": 2}, "ATTEMPT_LIMIT_DENIED"),
            ({"max_attempts": True}, "ATTEMPT_LIMIT_DENIED"),
            ({"max_cost_usd": 0.01}, "COST_LIMIT_DENIED"),
            ({"max_cost_usd": True}, "COST_LIMIT_DENIED"),
            ({"authority_sha256": "bogus"}, "ASSIGNMENT_DIGEST_INVALID"),
        ]
        for mutation, reason in cases:
            with self.subTest(case=mutation), self.assertRaisesRegex(a.Denied, reason):
                admit_sample(dict(sample(), **mutation))

    def test_stale_future_and_long_lifetime_denied(self):
        for mutation, reason in (
            ({"expires_at": "2026-10-14T15:59:59Z"}, "ASSIGNMENT_EXPIRED_OR_FUTURE"),
            ({"issued_at": "2026-10-14T16:02:00Z"}, "ASSIGNMENT_EXPIRED_OR_FUTURE"),
            ({"expires_at": "2026-10-14T17:00:00Z"}, "ASSIGNMENT_TTL_DENIED"),
            ({"expires_at": "2026-10-14T15:00:00Z"}, "ASSIGNMENT_TTL_DENIED"),
            ({"issued_at": "2026-10-14 15:59:00"}, "ASSIGNMENT_TIMESTAMP_INVALID"),
        ):
            with self.subTest(case=mutation), self.assertRaisesRegex(a.Denied, reason):
                admit_sample(dict(sample(), **mutation))

    def test_independent_replay_identity_required(self):
        doc = sample()
        for prior in ([("test-delegated-cpu-001", "f"*32)],
                      [("another-assignment", "1"*32)]):
            with self.subTest(prior=prior), self.assertRaisesRegex(a.Denied, "REPLAY_OR_DUPLICATE"):
                admit_sample(doc, prior_identities=prior)
        with self.assertRaisesRegex(a.Denied, "REPLAY_EVIDENCE_INVALID"):
            admit_sample(doc, prior_identities=[None])

    def test_duplicate_json_and_bounded_untrusted_input(self):
        raw = json.dumps(sample())
        forged = raw.replace('"max_attempts": 1', '"max_attempts": 1, "max_attempts": 1')
        with self.assertRaisesRegex(a.Denied, "DUPLICATE_ASSIGNMENT_FIELD"):
            a.admit(forged, trusted_source_sha=SOURCE, now=NOW)
        with self.assertRaisesRegex(a.Denied, "ASSIGNMENT_BYTES_INVALID"):
            a.admit(raw + " " * 5000, trusted_source_sha=SOURCE, now=NOW)

    def test_zero_new_scheduler_or_shell_authority(self):
        source = (ROOT / "scripts" / "gha_assignment_contract.py").read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("subprocess.run", source)
        self.assertNotIn("workflow_dispatch(", source)


if __name__=="__main__":
    unittest.main()
