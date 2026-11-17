#!/usr/bin/env python3
"""Agent Dispatch #485: typed, no-secret GHA request -> fixed CPU workload.

This is a binding/planner, not a scheduler. Only committed, reviewed JSON from
a fixed repository directory and a fixed workload/runner allowlist is admitted.
Never execute argv/shell/code/URL received from a request. No credential access.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

SCHEMA = "gha-workload-request/v1"
RECEIPT = "gha-workload-receipt/v1"
ROOT = Path(__file__).resolve().parents[1]
REQUEST_DIR = ROOT / "requests" / "gha"
SAFE_PATH = re.compile(r"^requests/gha/[a-z0-9][a-z0-9-]{2,63}\.json$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")
SHAPES = {"ubuntu-24.04": "x86_64", "ubuntu-24.04-arm": "aarch64"}
WORKLOADS = {"arithmetic-oracle", "sealed-contract-native", "microsoft-devproxy-mock", "azurite-blob-transport", "mail-synthetic-baseline", "mail-openworker-policy", "mail-ragmail-loss-witness", "mail-evidence-go-challenge", "mail-openworker-headless-mail", "mail-openworker-scripted", "wyse-r52-linux-guest"}
FIELDS = {"schema", "assignment_id", "runner", "workload", "timeout_seconds",
          "data_class", "max_attempts", "max_cost_usd"}
MAX_BYTES = 4096


class Denied(ValueError):
    pass


def read_request(name: str) -> tuple[dict, str]:
    if not SAFE_PATH.fullmatch(name):
        raise Denied("REQUEST_PATH_NOT_ALLOWED")
    path = ROOT / name
    if path.is_symlink() or not path.is_file() or path.resolve().parent != REQUEST_DIR.resolve():
        raise Denied("REQUEST_NOT_REVIEWED_LOCAL_FILE")
    raw = path.read_bytes()
    if len(raw) < 10 or len(raw) > MAX_BYTES:
        raise Denied("REQUEST_BYTES_OUT_OF_BOUNDS")
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Denied("REQUEST_JSON_INVALID") from exc
    if not isinstance(obj, dict) or set(obj) != FIELDS or obj.get("schema") != SCHEMA:
        raise Denied("REQUEST_SCHEMA_NOT_ALLOWED")
    if not isinstance(obj["assignment_id"], str) or not SAFE_ID.fullmatch(obj["assignment_id"]):
        raise Denied("ASSIGNMENT_ID_INVALID")
    if not isinstance(obj["runner"], str) or obj["runner"] not in SHAPES:
        raise Denied("RUNNER_SHAPE_NOT_ALLOWED")
    if not isinstance(obj["workload"], str) or obj["workload"] not in WORKLOADS:
        raise Denied("WORKLOAD_NOT_ALLOWED")
    if type(obj["timeout_seconds"]) is not int or not 1 <= obj["timeout_seconds"] <= 240:
        raise Denied("RUNTIME_BUDGET_OUT_OF_BOUNDS")
    if obj["data_class"] != "public-synthetic":
        raise Denied("DATA_CLASS_NOT_ALLOWED")
    if type(obj["max_attempts"]) is not int or obj["max_attempts"] != 1:
        raise Denied("ATTEMPT_BUDGET_OUT_OF_BOUNDS")
    if type(obj["max_cost_usd"]) not in (int, float) or obj["max_cost_usd"] != 0:
        raise Denied("COST_BUDGET_NOT_ZERO")
    return obj, hashlib.sha256(raw).hexdigest()


def plan(name: str) -> dict:
    doc, digest = read_request(name)
    return {
        "schema": SCHEMA,
        "request_path": name,
        "request_sha256": digest,
        "assignment_id": doc["assignment_id"],
        "runner": doc["runner"],
        "expected_machine": SHAPES[doc["runner"]],
        "workload": doc["workload"],
        "timeout_seconds": doc["timeout_seconds"],
        "data_class": doc["data_class"],
        "max_attempts": 1,
        "max_cost_usd": 0,
        "operation": "cpu-public-safe",
        "source_ref": "checked-out-default-branch",
    }


def _execute(workload: str, timeout: int) -> dict:
    if workload == "wyse-r52-linux-guest":
        # The same reviewed profile is used by the existing typed executor
        # and the R52 public disposable Linux guest. This is NOT a Wyse
        # physical host KVM/lease, and it does not call Agent Dispatch again.
        receipt = ROOT / "evidence/public/r52-linux-guest.txt"
        if receipt.is_symlink() or receipt.exists():
            return {"oracle_verified": False, "classification": "FAIL_STALE_GUEST_RECEIPT",
                    "guest_task_sha256": None, "guest_kernel_boot": False,
                    "guest_clean_exit": False, "physical_wyse_qualified": False,
                    "agent_dispatch_real_lease": False}
        try:
            cp = subprocess.run(
                ["bash", "tools/wyse-qemu-bootbench/run-linux-guest.sh",
                 "--public-disposable"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "guest_task_sha256": None, "guest_kernel_boot": False,
                    "guest_clean_exit": False, "physical_wyse_qualified": False,
                    "agent_dispatch_real_lease": False}
        if cp.returncode != 0 or receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > 1600:
            return {"oracle_verified": False, "classification": "FAIL_LINUX_GUEST",
                    "guest_task_sha256": None, "guest_kernel_boot": False,
                    "guest_clean_exit": False, "physical_wyse_qualified": False,
                    "agent_dispatch_real_lease": False}
        try:
            pairs = [line.split("=", 1) for line in receipt.read_text(encoding="utf-8").splitlines()]
            evidence = {k: v for k, v in pairs}
            valid = (
                len(pairs) == 7 and len(evidence) == 7 and
                evidence.get("R52_C_EVIDENCE_CLASS") == "PUBLIC_DISPOSABLE_REAL_LINUX_NOT_DELL_HIL" and
                evidence.get("R52_C_GUEST_BOOT") == "LINUX_KERNEL_QEMU_TCG_OBSERVED" and
                evidence.get("R52_C_GUEST_TASK_SHA256") ==
                "b4f51231b5956ff6eb520c4a85dc43ff4542405342e5ab8e097b960155898782" and
                evidence.get("R52_C_HOST_VOLUME_AND_GUEST_NIC") == "NOT_ATTACHED" and
                evidence.get("R52_C_AGENT_DISPATCH_REAL_LEASE") == "NOT_TESTED" and
                evidence.get("R52_C_WYSE_REAL_KVM_AND_EMMC") == "NOT_TESTED" and
                evidence.get("R52_C_GUEST_RESULT_AND_CLEAN_EXIT") == "PASS")
        except (OSError, ValueError, UnicodeError):
            valid = False
        return {
            "oracle_verified": bool(valid),
            "classification": "PASS" if valid else "FAIL_GUEST_RECEIPT",
            "guest_task_sha256": evidence["R52_C_GUEST_TASK_SHA256"] if valid else None,
            "guest_kernel_boot": bool(valid),
            "guest_clean_exit": bool(valid),
            "physical_wyse_qualified": False,
            "agent_dispatch_real_lease": False,
        }
    if workload == "azurite-blob-transport":
        # Fixed source, no input-substituted command, public Azurite emulator account only.
        try:
            cp = subprocess.run(
                ["bash", "scripts/qualify_azurite_transport.sh"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "emulator_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        p = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")) / "azurite-blob" / "verified.json"
        if cp.returncode != 0 or p.is_symlink() or not p.is_file() or p.stat().st_size > 8192:
            return {"oracle_verified": False, "classification": "FAIL_EMULATOR",
                    "emulator_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        raw = p.read_bytes()
        try:
            verdict = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            verdict = {}
        accepted = (
            isinstance(verdict, dict) and
            verdict.get("schema") == "azurite-transport-independent-verdict/v1" and
            verdict.get("classification") == "EMULATOR_ONLY_PASS" and
            verdict.get("provider_access_verified") is False and
            verdict.get("revision_changed") is True and
            verdict.get("write_replay_blocked") is True and
            verdict.get("stale_write_blocked") is True and
            verdict.get("stale_read_blocked") is True and
            verdict.get("fresh_client_recovered") is True and
            verdict.get("source_sha") == os.environ.get("GITHUB_SHA") and
            verdict.get("native_run_id") == os.environ.get("GITHUB_RUN_ID"))
        return {"oracle_verified": bool(accepted),
                "classification": "PASS" if accepted else "FAIL_EMULATOR_VERDICT",
                "emulator_only": True, "provider_access_verified": False,
                "verdict_sha256": hashlib.sha256(raw).hexdigest() if accepted else None}
    if workload == "microsoft-devproxy-mock":
        # Fixed reviewed public-synthetic source only; never shell-interpolated inputs.
        try:
            cp = subprocess.run(
                ["bash", "scripts/qualify_microsoft_devproxy.sh"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "mock_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        verdict_path = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")) / "microsoft-mock" / "verified.json"
        if cp.returncode != 0 or not verdict_path.is_file():
            return {"oracle_verified": False, "classification": "FAIL_MOCK_CANARY",
                    "mock_only": True, "provider_access_verified": False,
                    "verdict_sha256": None}
        raw = verdict_path.read_bytes()
        try:
            verdict = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            verdict = {}
        accepted = (isinstance(verdict, dict) and
                    verdict.get("classification") == "MOCK_ONLY_PASS" and
                    verdict.get("verified") is True and
                    verdict.get("provider_access_verified") is False and
                    verdict.get("source_sha") == os.environ.get("GITHUB_SHA") and
                    verdict.get("run_id") == os.environ.get("GITHUB_RUN_ID"))
        return {"oracle_verified": bool(accepted),
                "classification": "PASS" if accepted else "FAIL_MOCK_VERDICT",
                "mock_only": True, "provider_access_verified": False,
                "verdict_sha256": hashlib.sha256(raw).hexdigest() if accepted else None}
    if workload == "mail-openworker-scripted":
        # Exact source-pinned public MIT OpenWorker engine only; disposable venv.
        # All runtime inference is fake scripted-model replay, no real mailbox.
        try:
            cp = subprocess.run(
                [sys.executable, "scripts/qualify_openworker_scripted_runtime.py"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
            if cp.returncode != 0 or len(cp.stdout) > 8192:
                raise ValueError("ORIGINAL_SCRIPTED_RUNTIME_FAILED")
            result = json.loads(cp.stdout)
            admitted = (
                isinstance(result, dict)
                and result.get("schema") == "public-openworker-scripted-full-runtime/v1"
                and result.get("classification") == "ORIGINAL_SCRIPTED_HEADLESS_RUNTIME_ONLY"
                and result.get("upstream_commit") == "ecb445490fc054d52b8ea610d97ba947f57033d2"
                and result.get("upstream_license") == "MIT"
                and result.get("headless_engine_executed") is True
                and result.get("model_inference") is False
                and result.get("scripted_provider_only") is True
                and result.get("real_mail") is False
                and result.get("smtp_sent") is False
                and result.get("shell_tools_executed") is False
                and result.get("approval_denial_observed") is True
                and result.get("clean_restart_replay") is True
                and result.get("atif_schema") == "ATIF-v1.7"
                and result.get("run_count") == 2
                and result.get("record_count_per_run") == 7
                and result.get("installed_package_count", 0) >= 1
                and result.get("dependencies_hash_locked") is False
                and result.get("total_denied_calls", 0) >= 2
                and result.get("total_model_calls", 0) >= 2
                and isinstance(result.get("dependency_inventory_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", result["dependency_inventory_sha256"]) is not None
                and type(result.get("venv_size_bytes")) is int
                and result["venv_size_bytes"] > 0
                and type(result.get("install_seconds")) in (float, int)
                and type(result.get("elapsed_seconds")) in (float, int))
        except (OSError, ValueError, subprocess.TimeoutExpired):
            admitted, result, cp = False, {}, None
        return {
            "oracle_verified": bool(admitted),
            "classification": "PASS" if admitted else "FAIL_SCRIPTED_ENGINE_OR_INSTALL",
            "source_commit": result.get("upstream_commit") if admitted else None,
            "scripted_provider_only": bool(admitted),
            "headless_engine_executed": bool(admitted),
            "approval_denial_verified": bool(admitted),
            "clean_restart_verified": bool(admitted),
            "real_mail": False,
            "model_inference": False,
            "dependency_hash_locked": False,
            "atif_schema": "ATIF-v1.7" if admitted else None,
            "run_count": 2 if admitted else 0,
            "denied_calls": result.get("total_denied_calls", 0) if admitted else 0,
            "package_count": result.get("installed_package_count", 0) if admitted else 0,
            "dependency_sha256": result.get("dependency_inventory_sha256") if admitted else None,
            "venv_size_bytes": result.get("venv_size_bytes", 0) if admitted else 0,
            "elapsed_seconds": result.get("elapsed_seconds", 0) if admitted else 0,
            "verdict_sha256": hashlib.sha256(cp.stdout).hexdigest() if admitted else None,
        }
    if workload == "mail-openworker-headless-mail":
        # Original immutable MIT headless CLI parser and fake IMAP source.
        # No real login, mail sending, model engine or arbitrary URL input.
        try:
            proc = subprocess.run(
                [sys.executable, "scripts/qualify_openworker_headless_mail.py"],
                cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
            if proc.returncode or len(proc.stdout) > 8192:
                raise ValueError("UPSTREAM_HEADLESS_FAKE_RUNTIME")
            observed = json.loads(proc.stdout)
            accepted = (
                isinstance(observed, dict)
                and observed.get("schema") == "public-openworker-headless-mail-contract/v1"
                and observed.get("classification") == "UPSTREAM_HEADLESS_AND_FAKE_IMAP_ONLY"
                and observed.get("upstream_repository") == "andrewyng/openworker"
                and observed.get("upstream_commit") ==
                    "ecb445490fc054d52b8ea610d97ba947f57033d2"
                and observed.get("connector_blob_sha") ==
                    "7be4e1f9e78e8fd9d1ef81b58bbc86a916c48e76"
                and observed.get("headless_blob_sha") ==
                    "3cadae25bd4a3c90d363ae296522058e578af917"
                and observed.get("license") == "MIT"
                and observed.get("qualified") is True
                and observed.get("control_count") == 12
                and observed.get("isolated_defaults") is True
                and observed.get("fake_mail_readonly") is True
                and observed.get("duplicate_attachments_visible") is True
                and observed.get("no_smtp_attempts") is True
                and observed.get("same_name_second_unaddressable") is True
                and observed.get("attachment_download_occurrence_complete") is False
                and observed.get("approval_metadata_only") is True
                and observed.get("headless_engine_run") is False
                and observed.get("model_inference") is False
                and observed.get("real_mail") is False)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            accepted = False
            observed = {}
            proc = None
        return {
            "oracle_verified": bool(accepted),
            "classification": "PASS" if accepted else "FAIL_UPSTREAM_HEADLESS_MAIL",
            "upstream_commit": observed.get("upstream_commit") if accepted else None,
            "connector_blob_sha": observed.get("connector_blob_sha") if accepted else None,
            "headless_blob_sha": observed.get("headless_blob_sha") if accepted else None,
            "control_count": 12 if accepted else 0,
            "fake_readonly": bool(accepted),
            "duplicate_attachments_visible": bool(accepted),
            "no_smtp_attempts": bool(accepted),
            "same_name_second_unaddressable": bool(accepted),
            "attachment_download_occurrence_complete": False,
            "isolated_defaults": bool(accepted),
            "real_mail": False,
            "model_inference": False,
            "headless_engine_run": False,
            "verdict_sha256": hashlib.sha256(proc.stdout).hexdigest() if accepted else None,
        }
    if workload == "mail-evidence-go-challenge":
        # Exact repository-controlled Go source, standard library and immutable
        # fictional gold. Neither a dynamic command nor a model provider.
        package_root = ROOT / "tools" / "mail-evidence-challenge"
        environment = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off",
                           GOSUMDB="off", GOFLAGS="-mod=readonly")
        if not (package_root / "go.mod").is_file():
            return {"oracle_verified": False, "classification": "FAIL_PACKAGE",
                    "typed_only": True, "model_inference": False,
                    "question_count": 0, "source_occurrences": 0,
                    "attachment_occurrences": 0, "false_merge_count": 0,
                    "cross_tenant_leaks": 0, "restart_verified": False,
                    "native_pst_qualified": False, "corpus_sha256": None,
                    "verdict_sha256": None}
        try:
            checked = subprocess.run(
                ["go", "test", "-count=2", "./..."], cwd=package_root,
                env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
            if checked.returncode or len(checked.stdout) > 32768:
                raise ValueError("GO_TEST_FAILED")
            run = subprocess.run(
                ["go", "run", "./cmd/evidence"], cwd=package_root,
                env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
            if run.returncode or len(run.stdout) > 8192:
                raise ValueError("GO_CHALLENGE_FAILED")
            result = json.loads(run.stdout)
            accepted = (
                isinstance(result, dict)
                and result.get("Schema") == "mail-public-evidence-challenge/v1"
                and result.get("Classification") == "SYNTHETIC_TYPED_EVIDENCE_ONLY"
                and result.get("SourceOccurrences") == 8
                and result.get("AttachmentOccurrences") == 5
                and result.get("QuestionCount") == 21
                and result.get("VerifiedQuestions") == 21
                and result.get("FalseMergeCount") == 0
                and result.get("CrossTenantLeaks") == 0
                and result.get("IndependentGold") is True
                and result.get("PersistenceRecovery") is True
                and result.get("ModelInference") is False
                and result.get("NativePSTConformance") == "NOT_TESTED"
                and isinstance(result.get("CorpusSHA256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", result["CorpusSHA256"]) is not None)
        except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
            accepted = False
            result = {}
            run = None
        return {
            "oracle_verified": bool(accepted),
            "classification": "PASS" if accepted else "FAIL_TYPED_GOLD_OR_RUNTIME",
            "typed_only": True, "model_inference": False,
            "question_count": result.get("VerifiedQuestions", 0) if accepted else 0,
            "source_occurrences": result.get("SourceOccurrences", 0) if accepted else 0,
            "attachment_occurrences": result.get("AttachmentOccurrences", 0) if accepted else 0,
            "false_merge_count": result.get("FalseMergeCount", 0) if accepted else 0,
            "cross_tenant_leaks": result.get("CrossTenantLeaks", 0) if accepted else 0,
            "restart_verified": bool(accepted),
            "native_pst_qualified": False,
            "corpus_sha256": result.get("CorpusSHA256") if accepted else None,
            "verdict_sha256": hashlib.sha256(run.stdout).hexdigest() if accepted else None,
        }
    if workload == "mail-ragmail-loss-witness":
        # An independent **negative** source-occurrence oracle against public MIT
        # RAG-Mail original code; a PASS proves product-incompatible loss exists.
        try:
            cp = subprocess.run(
                [sys.executable, "scripts/qualify_ragmail_mbox_loss.py"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "upstream_commit": None, "source_blob_sha": None,
                    "evidence_loss_confirmed": False, "dropped_messages": 0,
                    "dropped_attachments": 0, "reader_qualified": False,
                    "verdict_sha256": None}
        raw = cp.stdout[:8193]
        if cp.returncode != 0 or len(cp.stdout) > 8192:
            return {"oracle_verified": False, "classification": "FAIL_WITNESS_RUNTIME",
                    "upstream_commit": None, "source_blob_sha": None,
                    "evidence_loss_confirmed": False, "dropped_messages": 0,
                    "dropped_attachments": 0, "reader_qualified": False,
                    "verdict_sha256": None}
        try:
            obs = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            obs = {}
        accepted = (
            isinstance(obs, dict)
            and obs.get("schema") == "public-ragmail-mbox-loss-witness/v1"
            and obs.get("classification") == "EXPECTED_EVIDENCE_LOSS_WITNESS"
            and obs.get("upstream_repository") == "ManiAm/RAG-Mail"
            and obs.get("upstream_commit") ==
                "afab46bfdd83d11af8bacee8231871ff1292fced"
            and obs.get("upstream_source_blob") ==
                "5a9ee91a0f1b7d04439ab8808bf7b1c88df868d6"
            and obs.get("license") == "MIT"
            and obs.get("input_source_occurrences") == 3
            and obs.get("stored_messages") == 1
            and obs.get("input_attachment_occurrences") == 2
            and obs.get("stored_attachments") == 1
            and obs.get("dropped_message_occurrences") == 2
            and obs.get("dropped_attachment_occurrences") == 1
            and obs.get("canonical_evidence_compatible") is False
            and obs.get("expected_loss_reproduced") is True
            and obs.get("real_database_used") is False
            and obs.get("real_mail_used") is False
            and obs.get("model_inference") is False
            and obs.get("cost_usd") == 0)
        return {
            "oracle_verified": bool(accepted),
            "classification": "PASS" if accepted else "FAIL_LOSS_WITNESS",
            "upstream_commit": obs.get("upstream_commit") if accepted else None,
            "source_blob_sha": obs.get("upstream_source_blob") if accepted else None,
            "evidence_loss_confirmed": bool(accepted),
            "dropped_messages": 2 if accepted else 0,
            "dropped_attachments": 1 if accepted else 0,
            "reader_qualified": False,
            "verdict_sha256": hashlib.sha256(raw).hexdigest() if accepted else None,
        }
    if workload == "mail-openworker-policy":
        # Exact Git-blob-pinned MIT upstream read-only policy modules only.
        # The request never carries a URL, command or permission widening.
        try:
            cp = subprocess.run(
                [sys.executable, "scripts/qualify_openworker_readonly.py"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "model_inference": False, "mail_credential_access": False,
                    "source_blob_sha": None, "control_count": 0,
                    "upstream_commit": None, "verdict_sha256": None}
        raw = cp.stdout[:8193]
        if cp.returncode or len(cp.stdout) > 8192:
            return {"oracle_verified": False, "classification": "FAIL_UPSTREAM_PROBE",
                    "model_inference": False, "mail_credential_access": False,
                    "source_blob_sha": None, "control_count": 0,
                    "upstream_commit": None, "verdict_sha256": None}
        try:
            observed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            observed = {}
        cases = observed.get("case_matrix", {}) if isinstance(observed, dict) else {}
        accepted = (
            isinstance(observed, dict)
            and observed.get("schema") == "openworker-public-policy-interview/v1"
            and observed.get("classification") == "UPSTREAM_POLICY_PRIMITIVES_ONLY"
            and observed.get("upstream_repository") == "andrewyng/openworker"
            and observed.get("upstream_commit") ==
                "ecb445490fc054d52b8ea610d97ba947f57033d2"
            and observed.get("readonly_blob_sha") ==
                "d621e606eea85be031c27237b0bc2ffcdfe590cb"
            and observed.get("license") == "MIT"
            and observed.get("qualified") is True
            and observed.get("model_inference") is False
            and observed.get("mail_credential_access") is False
            and observed.get("shell_commands_executed") is False
            and observed.get("network_origin") == "raw.githubusercontent.com"
            and isinstance(cases, dict)
            and cases.get("allowed_controls") == 2
            and cases.get("blocked_controls") == 6
            and cases.get("safe_all_allowed") is True
            and cases.get("dangerous_all_rejected") is True
            and cases.get("host_normalization_verified") is True
            and cases.get("unknown_network_profile_rejected") is True)
        return {"oracle_verified": bool(accepted),
                "classification": "PASS" if accepted else "FAIL_UPSTREAM_ORACLE",
                "model_inference": False, "mail_credential_access": False,
                "source_blob_sha": observed.get("readonly_blob_sha")
                    if accepted else None,
                "control_count": 8 if accepted else 0,
                "upstream_commit": observed.get("upstream_commit")
                    if accepted else None,
                "verdict_sha256": hashlib.sha256(raw).hexdigest()
                    if accepted else None}
    if workload == "mail-synthetic-baseline":
        # Only the reviewed self-generated fixture + independent negative suite.
        # Infrastructure and retrieval result only, never semantic LLM success.
        try:
            cp = subprocess.run(
                [sys.executable, "-m", "unittest", "discover",
                 "-s", "tests", "-p", "test_mail_synthetic_baseline.py"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT",
                    "retrieval_only": True, "model_inference": False,
                    "query_count": 0, "fixture_sha256": None}
        if cp.returncode:
            return {"oracle_verified": False, "classification": "FAIL_TESTS",
                    "retrieval_only": True, "model_inference": False,
                    "query_count": 0, "fixture_sha256": None}
        if str(ROOT / "scripts") not in sys.path:
            sys.path.insert(0, str(ROOT / "scripts"))
        from mail_synthetic_baseline import benchmark
        result = benchmark()
        accepted = (
            result["classification"] == "RETRIEVAL_ONLY_SYNTHETIC"
            and result["queries"] == 9
            and result["retrieval_recall_at_3"] == 1
            and result["no_occurrence_loss"] is True
            and result["cross_tenant_leakage"] is False
            and result["unknown_invented"] is False
            and result["model_inference"] is False
            and result["native_pst_conformance"] == "NOT_TESTED")
        return {"oracle_verified": bool(accepted),
                "classification": "PASS" if accepted else "FAIL_RETRIEVAL_ORACLE",
                "retrieval_only": True, "model_inference": False,
                "query_count": result["queries"],
                "fixture_sha256": result["corpus_sha256"]}
    if workload == "arithmetic-oracle":
        nums = [i*i for i in range(256)]
        ok = sum(nums) == 5559680 and len(nums) == 256
        return {"oracle_verified": ok, "classification": "PASS" if ok else "FAIL_MATH",
                "task_count": len(nums),
                "fixture_sha256": hashlib.sha256(
                    json.dumps(nums, separators=(",", ":")).encode()).hexdigest()}
    if workload == "sealed-contract-native":
        try:
            cp = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests",
                 "-p", "test_sealed_public_execution.py"],
                cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return {"oracle_verified": False, "classification": "FAIL_TIMEOUT"}
        return {"oracle_verified": cp.returncode == 0,
                "classification": "PASS" if cp.returncode == 0 else "FAIL_TESTS"}
    raise Denied("WORKLOAD_NOT_ALLOWED")


def run(name: str, expected_digest: str) -> dict:
    p = plan(name)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or expected_digest != p["request_sha256"]:
        raise Denied("REQUEST_DIGEST_CHANGED")
    system = platform.system()
    machine = platform.machine()
    runner_arch = os.environ.get("RUNNER_ARCH", "")
    verified = system == "Linux" and machine == p["expected_machine"] and (
        runner_arch in (("X64",) if machine == "x86_64" else ("ARM64",))
    )
    result = _execute(p["workload"], p["timeout_seconds"]) if verified else {
        "classification": "FAIL_RUNNER_SHAPE", "oracle_verified": False,
    }
    return {
        "schema": RECEIPT,
        "assignment_id": p["assignment_id"],
        "request_sha256": p["request_sha256"],
        "request_path": name,
        "workload": p["workload"],
        "requested_runner": p["runner"],
        "observed_architecture": machine if system == "Linux" else "unqualified",
        "shape_verified": verified,
        "data_class": "public-synthetic",
        "source_sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "result": result,
        "qualified": verified and result["oracle_verified"] is True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=["plan", "run"], required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--digest", default="")
    parser.add_argument("--github-output")
    parser.add_argument("--receipt")
    opts = parser.parse_args()
    try:
        p = plan(opts.request)
        if opts.action == "plan":
            if opts.github_output:
                with open(opts.github_output, "a", encoding="utf-8") as fh:
                    for key in ("runner", "request_sha256", "assignment_id"):
                        fh.write(f"{key}={p[key]}\n")
            print(json.dumps(p, sort_keys=True))
            return 0
        if not opts.receipt:
            raise Denied("RECEIPT_PATH_REQUIRED")
        result = run(opts.request, opts.digest)
        encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
        dest = Path(opts.receipt)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(encoded, encoding="utf-8")
        print("GHA_REQUEST_QUALIFIED=" + str(result["qualified"]).lower())
        print("GHA_RECEIPT_SHA256=" + hashlib.sha256(encoded.encode()).hexdigest())
        return 0 if result["qualified"] else 2
    except (Denied, OSError):
        print("GHA_REQUEST_BLOCKED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
