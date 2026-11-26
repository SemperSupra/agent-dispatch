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
WORKLOADS = {"arithmetic-oracle", "sealed-contract-native", "microsoft-devproxy-mock", "azurite-blob-transport", "mail-synthetic-baseline", "mail-openworker-policy", "mail-ragmail-loss-witness", "mail-evidence-go-challenge", "mail-openworker-headless-mail", "mail-openworker-scripted", "mail-temporal-swipl-r2","mail-temporal-postgres-r2", "mail-temporal-xtdb-r2","mail-xtdb-frozen-oracle-r3", "mail-qwen-real-cpu"}
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
    if obj["workload"] == "mail-qwen-real-cpu":
        if (name != "requests/gha/mail-qwen-real-cpu-v1.json" or
                obj["assignment_id"] != "mail-qwen-real-cpu-v1" or
                obj["runner"] != "ubuntu-24.04" or
                type(obj["timeout_seconds"]) is not int or obj["timeout_seconds"] != 420):
            raise Denied("MODEL_FIXED_PROFILE_REQUIRED")
    elif type(obj["timeout_seconds"]) is not int or not 1 <= obj["timeout_seconds"] <= 240:
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
    if workload == "mail-temporal-swipl-r2":
        # This fixed program is the original installed SWI-Prolog interpreter
        # reading only a reviewed static fictional Prolog source file.
        try:
            cp=subprocess.run(
                [sys.executable,"scripts/qualify_temporal_swipl.py"],
                cwd=ROOT,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                timeout=timeout,check=False)
            if cp.returncode or len(cp.stdout)>8192:
                raise ValueError("NATIVE_SWIPL_QUIFICATION_FAILED")
            observed=json.loads(cp.stdout)
            admitted=(isinstance(observed,dict)
                and observed.get("schema")=="public-mail-temporal-original-swi-prolog-r2"
                and observed.get("classification")=="PASS_ORIGINAL_SWI_LOGIC_ONLY"
                and observed.get("native_engine_executed") is True
                and observed.get("clean_replay_verified") is True
                and observed.get("support_and_refutation_retained") is True
                and observed.get("cross_tenant_blocked") is True
                and observed.get("derivation_quarantined") is True
                and observed.get("model_inference") is False
                and observed.get("native_pst_qualified") is False
                and observed.get("source_occurrences")==8
                and observed.get("independent_test_cases")==9
                and isinstance(observed.get("interpreter_version"),str)
                and observed["interpreter_version"].startswith("SWI-Prolog version 9.")
                and isinstance(observed.get("source_sha256"),str)
                and re.fullmatch(r"[0-9a-f]{64}",observed["source_sha256"]) is not None
                and isinstance(observed.get("stdout_sha256"),str)
                and re.fullmatch(r"[0-9a-f]{64}",observed["stdout_sha256"]) is not None)
        except (ValueError,OSError,subprocess.TimeoutExpired):
            admitted,observed,cp=False,{},None
        return {
            "oracle_verified":bool(admitted),
            "classification":"PASS" if admitted else "FAIL_NATIVE_PROLOG",
            "native_engine_executed":bool(admitted),
            "interpreter_version":observed.get("interpreter_version") if admitted else None,
            "source_sha256":observed.get("source_sha256") if admitted else None,
            "clean_replay_verified":bool(admitted),
            "source_occurrences":8 if admitted else 0,
            "independent_test_cases":9 if admitted else 0,
            "contradiction_preserved":bool(admitted),
            "derivation_quarantined":bool(admitted),
            "cross_tenant_blocked":bool(admitted),
            "model_inference":False,
            "native_pst_qualified":False,
            "verdict_sha256":hashlib.sha256(cp.stdout).hexdigest() if admitted else None,
        }
    if workload == "mail-temporal-postgres-r2":
        # Actual official PG18 server in one ephemeral no-port Docker container.
        # Fixed original container digest and fixed source fixture only.
        try:
            cp=subprocess.run(
                [sys.executable,"scripts/qualify_temporal_postgres18.py"],
                cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=timeout,check=False)
            if cp.returncode or len(cp.stdout)>8192:
                error=re.search(r"POSTGRES_FIRST_FAILURE=([A-Z0-9_]{3,90})",
                    cp.stderr.decode("ascii","replace")[:1024])
                print("MAIL_POSTGRES_FIRST_FAILURE="+
                    (error.group(1) if error else "UNCLASSIFIED_RUNTIME"),
                    flush=True)
                raise ValueError("NATIVE_POSTGRES_RUN_FAILED")
            observed=json.loads(cp.stdout)
            admitted=(
                isinstance(observed,dict)
                and observed.get("schema")=="mail-temporal-native-postgresql18-r2"
                and observed.get("classification")=="NATIVE_POSTGRES18_TEMPORAL_ONLY"
                and observed.get("postgres_version","").startswith("18.7")
                and observed.get("image_digest")=="e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61"
                and observed.get("image_immutable") is True
                and observed.get("qualified_cases")==8
                and observed.get("source_occurrences")==6
                and observed.get("claims")==6
                and observed.get("four_valued_source_support") is True
                and observed.get("valid_at_and_known_at_separate") is True
                and observed.get("overlap_constraint_qualified") is True
                and observed.get("same_source_overlap_denied") is True
                and observed.get("different_source_overlap_preserved") is True
                and observed.get("cross_tenant_denied") is True
                and observed.get("immutable_source_denied") is True
                and observed.get("restart_verified") is True
                and observed.get("local_only_no_published_ports") is True
                and observed.get("model_inference") is False
                and observed.get("native_pst_qualified") is False
                and isinstance(observed.get("fixture_sha256"),str)
                and re.fullmatch(r"[0-9a-f]{64}",observed["fixture_sha256"]) is not None
                and type(observed.get("elapsed_seconds")) in (float,int)
                and 0<=observed["elapsed_seconds"]<=timeout)
        except (ValueError,OSError,subprocess.TimeoutExpired,AttributeError,TypeError):
            admitted,observed,cp=False,{},None
        return {
            "oracle_verified":bool(admitted),
            "classification":"PASS" if admitted else "FAIL_POSTGRES_NATIVE",
            "native_postgres_executed":bool(admitted),
            "engine_version":observed.get("postgres_version") if admitted else None,
            "image_digest":observed.get("image_digest") if admitted else None,
            "source_occurrences":6 if admitted else 0,
            "qualified_cases":8 if admitted else 0,
            "valid_knowledge_separate":bool(admitted),
            "same_source_overlap_denied":bool(admitted),
            "different_source_overlap_preserved":bool(admitted),
            "immutable_source_denied":bool(admitted),
            "restart_verified":bool(admitted),
            "cross_tenant_blocked":bool(admitted),
            "network_port_published":False,
            "model_inference":False,
            "native_pst_qualified":False,
            "fixture_sha256":observed.get("fixture_sha256") if admitted else None,
            "verdict_sha256":hashlib.sha256(cp.stdout).hexdigest() if admitted else None,
        }
    if workload == "mail-xtdb-frozen-oracle-r3":
        # Exact reviewed public fictional SQLite/PG source corpus compared
        # against original XTDB source/claims at two explicit time cutoffs.
        try:
            cp=subprocess.run(
                [sys.executable,"scripts/qualify_temporal_xtdb_frozen_oracle_r3.py"],
                cwd=ROOT,stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=timeout,check=False)
            if cp.returncode or len(cp.stdout)>8192:
                marker=re.search(r"XTDB_R3_FIRST_FAILURE=([A-Z0-9_]{3,90})",
                    cp.stderr.decode("ascii","replace")[:1024])
                print("MAIL_XTDB_R3_FIRST_FAILURE="+
                    (marker.group(1) if marker else "UNCLASSIFIED_SUBPROCESS"),
                    flush=True)
                raise ValueError("XTDB_R3_ORACLE_OR_RUNTIME_FAIL")
            observed=json.loads(cp.stdout)
            admitted=(
                isinstance(observed,dict)
                and observed.get("schema")=="mail-native-xtdb-frozen-eight-case-r3"
                and observed.get("classification")==
                    "ORIGINAL_XTDB_TWO_QUERY_APP_JOIN_TEMPORAL_GOLD"
                and observed.get("engine_digest")==
                    "aa7483e48674446a4892e0ea56a0953502fa5ccb9c4c803a9fb569ea5f0c28fe"
                and observed.get("client_digest")==
                    "e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61"
                and observed.get("same_frozen_eight_cases_verified") is True
                and observed.get("xtdb_native_sql_join_verified") is False
                and observed.get("adapter_source_join_verified") is True
                and observed.get("case_count")==8
                and observed.get("source_occurrences")==6
                and observed.get("claim_occurrences")==6
                and observed.get("cross_tenant_query_filtered") is True
                and observed.get("original_records_preserved") is True
                and observed.get("reacquired_lineage_not_extra_vote") is True
                and observed.get("planned_not_completed") is True
                and observed.get("restart_verified") is True
                and observed.get("xtdb_native_system_time_parity") is False
                and observed.get("xtdb_source_immutability_enforced") is False
                and observed.get("model_inference") is False
                and observed.get("native_pst_qualified") is False
                and observed.get("source_history_risk")==
                    "XTDB_UPSERT_ID_REQUIRES_APPLICATION_GUARD"
                and isinstance(observed.get("fixture_sha256"),str)
                and re.fullmatch(r"[0-9a-f]{64}",observed["fixture_sha256"]) is not None
                and type(observed.get("elapsed_seconds")) in (int,float)
                and 0<=observed["elapsed_seconds"]<=timeout)
        except (ValueError,OSError,TypeError,AttributeError,subprocess.TimeoutExpired):
            admitted,observed,cp=False,{},None
        return {
            "oracle_verified":bool(admitted),
            "classification":"PASS" if admitted else "FAIL_NATIVE_XTDB_PARITY",
            "native_xtdb_executed":bool(admitted),
            "engine_digest":observed.get("engine_digest") if admitted else None,
            "case_count":8 if admitted else 0,
            "source_occurrences":6 if admitted else 0,
            "claim_occurrences":6 if admitted else 0,
            "frozen_gold_parity":bool(admitted),
            "native_sql_join_verified":False,
            "adapter_source_join_verified":bool(admitted),
            "restart_verified":bool(admitted),
            "cross_tenant_filtered":bool(admitted),
            "source_upsert_risk":True,
            "native_system_time_parity":False,
            "native_source_immutability":False,
            "model_inference":False,
            "native_pst_qualified":False,
            "fixture_sha256":observed.get("fixture_sha256") if admitted else None,
            "verdict_sha256":hashlib.sha256(cp.stdout).hexdigest() if admitted else None,
        }
    if workload == "mail-temporal-xtdb-r2":
        # Public original XTDB GHCR digest, internal-network-only pgwire
        # and publisher's immutable original Postgres client image.
        try:
            cp=subprocess.run(
                [sys.executable,"scripts/qualify_temporal_xtdb.py"],
                cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=timeout,check=False)
            if cp.returncode or len(cp.stdout)>8192:
                failure=re.search(r"XTDB_FIRST_FAILURE=([A-Z0-9_]{3,85})",
                    cp.stderr.decode("ascii","replace")[:1024])
                print("MAIL_XTDB_FIRST_FAILURE="+
                    (failure.group(1) if failure else "UNCLASSIFIED_RUNTIME"),
                    flush=True)
                raise ValueError("NATIVE_XTDB_QUALIFICATION_FAILED")
            observed=json.loads(cp.stdout)
            admitted=(
                isinstance(observed,dict)
                and observed.get("schema")=="public-mail-xtdb-native-temporal-r2"
                and observed.get("classification")=="ORIGINAL_XTDB_BITEMPORAL_RUNTIME_ONLY"
                and observed.get("image_digest")==
                    "aa7483e48674446a4892e0ea56a0953502fa5ccb9c4c803a9fb569ea5f0c28fe"
                and observed.get("client_digest")==
                    "e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61"
                and observed.get("actual_xtdb_executed") is True
                and observed.get("source_occurrences")==3
                and observed.get("two_valid_time_queries") is True
                and observed.get("system_history_recorded") is True
                and type(observed.get("historical_record_count_at_least")) is int
                and observed["historical_record_count_at_least"]>=2
                and observed.get("separate_unique_source_keys") is True
                and observed.get("restart_verified") is True
                and observed.get("no_public_ports") is True
                and observed.get("different_source_conflict_preserved") is True
                and observed.get("source_upsert_is_application_risk") is True
                and observed.get("same_eight_case_oracle_qualified") is False
                and observed.get("model_inference") is False
                and observed.get("native_pst_qualified") is False
                and isinstance(observed.get("fixed_public_source_sha256"),str)
                and re.fullmatch(r"[0-9a-f]{64}",observed["fixed_public_source_sha256"]) is not None
                and type(observed.get("elapsed_seconds")) in (float,int)
                and 0<=observed["elapsed_seconds"]<=timeout)
        except (OSError,ValueError,subprocess.TimeoutExpired,TypeError,AttributeError):
            admitted,observed,cp=False,{},None
        return {
            "oracle_verified":bool(admitted),
            "classification":"PASS" if admitted else "FAIL_NATIVE_XTDB",
            "xtdb_engine_executed":bool(admitted),
            "image_digest":observed.get("image_digest") if admitted else None,
            "source_occurrences":3 if admitted else 0,
            "system_history_verified":bool(admitted),
            "valid_time_verified":bool(admitted),
            "restart_verified":bool(admitted),
            "private_internal_network":bool(admitted),
            "same_eight_case_oracle_qualified":False,
            "model_inference":False,
            "native_pst_qualified":False,
            "source_sha256":observed.get("fixed_public_source_sha256") if admitted else None,
            "verdict_sha256":hashlib.sha256(cp.stdout).hexdigest() if admitted else None,
        }
    if workload == "mail-qwen-real-cpu":
        try:
            cp = subprocess.run([sys.executable,"scripts/qualify_mail_qwen_real_cpu.py"],
                cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=timeout,check=False)
            if cp.returncode or len(cp.stdout)>16384:
                failure=re.search(r"MODEL_PUBLIC_REP_BLOCKED=([A-Za-z0-9_]{3,90})",
                    cp.stderr.decode("ascii","replace")[:1024])
                print("MAIL_MODEL_FIRST_FAILURE="+
                      (failure.group(1).upper() if failure else "UNCLASSIFIED_SUBPROCESS"),
                      flush=True)
                raise ValueError("PINNED_MODEL_RUNTIME_FAILED")
            obs=json.loads(cp.stdout)
            fields={"schema","model_inference","model_sha256","engine_commit",
                    "engine_asset_sha256","corpus_sha256","model_calls",
                    "automatic_promotion","transport","rows"}
            if (type(obs) is not dict or set(obs)!=fields or
                    obs["schema"]!="mail-public-real-cpu-model-doe/v3" or
                    obs["model_inference"] is not True or
                    obs["automatic_promotion"] is not False or
                    obs["transport"]!="pinned-loopback-completion" or
                    obs["model_sha256"]!="9ee36184e616dfc76df4f5dd66f908dbde6979524ae36e6cefb67f532f798cb8" or
                    obs["engine_commit"]!="b4c0e00a4fcc0287d0bb32fd7cb0d8b286af73ed" or
                    obs["engine_asset_sha256"]!="a9b243a3bc4ca172010e96c64062fc02afd1dc4f8b699716f813ae6845ada4c6" or
                    type(obs["rows"]) is not list or len(obs["rows"])!=20 or
                    type(obs["model_calls"]) is not int or obs["model_calls"]!=20):
                raise ValueError("MODEL_RECEIPT_SCOPE_INVALID")
            return {"classification":"PASS","oracle_verified":True,
                    **{k:v for k,v in obs.items() if k!="schema"},
                    "verdict_sha256":hashlib.sha256(cp.stdout).hexdigest()}
        except (OSError,ValueError,TypeError,subprocess.TimeoutExpired):
            return {"classification":"FAIL_REAL_MODEL_RUNTIME_OR_ORACLE","oracle_verified":False}
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
