#!/usr/bin/env python3
"""Exact-target GARM controller Foundry F0-F5 oracle on disposable TrueNAS."""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import pathlib
import secrets
import ssl
import string
import subprocess
import tempfile
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for

SCHEMA = "semper-supra.garm-truenas-f0-f5-control/1"
EXPECTED_APP_NAME = "rdte-t6-garm"
EXPECTED_IMAGE = "ghcr.io/sempersupra/garm-appliance@sha256:1af67841ddd4589e3798dcda8be49230565c849d07ab57fd05899432dcdabca9"
EXPECTED_CONTROLLER_SOURCE = "8a72cb23deacc712786945ac5e7ee63f8b4976d6"
EXPECTED_PROVIDER_SOURCE = "14535745dc3aa3c0b5466da7c704bca4d23dcec5"
EXPECTED_FIXTURE_DATASET = "rdtepool/garm-t6"
EXPECTED_FIXTURE_ROOT = "/mnt/rdtepool/garm-t6"
EXPECTED_CONFIG_DIR = EXPECTED_FIXTURE_ROOT + "/config"
EXPECTED_CONFIG_PATH = EXPECTED_CONFIG_DIR + "/config.toml"
EXPECTED_DB_PATH = EXPECTED_CONFIG_DIR + "/garm.db"
BOOTSTRAP_CONFIG = "garm-initial-config"
TLS_CERT_CONFIG = "garm-tls-certificate"
TLS_KEY_CONFIG = "garm-tls-private-key"
BOOTSTRAP_PLACEHOLDER = "__EPHEMERAL_NESTED_GARM_CONFIG__"
TLS_PREFIX = "__EPHEMERAL_NESTED_TLS__:"
REQUIRED_METHODS = {
    "system.version", "core.get_methods",
    "app.query", "app.config", "app.create", "app.update", "app.redeploy",
    "app.stop", "app.start", "app.delete",
    "pool.dataset.query", "pool.dataset.create", "pool.dataset.delete",
    "filesystem.mkdir", "filesystem.stat",
}


def canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def reconciliation_action(app_state, live_compose, desired_compose):
    if app_state is None:
        return "CREATE"
    if app_state in {"DEPLOYING", "STOPPING"}:
        return "WAIT"
    if app_state not in {"RUNNING", "STOPPED"}:
        return "FAIL_CLOSED"
    if not isinstance(live_compose, dict):
        return "FAIL_CLOSED"
    return (
        "NOOP"
        if canonical_sha256(live_compose) == canonical_sha256(desired_compose)
        else "UPDATE"
    )


def load_json(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain an object")
    return value


def normalize_secret_configs(compose: dict) -> dict:
    normalized = copy.deepcopy(compose)
    configs = normalized.get("configs") or {}
    if (
        BOOTSTRAP_CONFIG not in configs
        or TLS_CERT_CONFIG not in configs
        or TLS_KEY_CONFIG not in configs
    ):
        raise RuntimeError("GARM secret-bearing config inventory drifted")
    configs[BOOTSTRAP_CONFIG]["content"] = BOOTSTRAP_PLACEHOLDER
    configs[TLS_CERT_CONFIG]["content"] = TLS_PREFIX + TLS_CERT_CONFIG
    configs[TLS_KEY_CONFIG]["content"] = TLS_PREFIX + TLS_KEY_CONFIG
    return normalized


def load_control(
    directory: pathlib.Path,
    foundry_commit: str,
    target_version: str,
    expected_system_version: str,
    expected_middleware_commit: str,
    expected_profile_path: str,
    expected_profile_blob: str,
) -> tuple[dict, dict]:
    control = load_json(directory / "control.json")
    compose = load_json(directory / "compose.json")
    deployment = load_json(directory / "deployment.json")

    if control.get("schema") != SCHEMA:
        raise RuntimeError("unexpected GARM F0-F5 control schema")
    if control.get("foundry_ref") != foundry_commit:
        raise RuntimeError("Foundry source ref drifted")
    target = control.get("target") or {}
    expected_target = {
        "truenas_version": target_version,
        "expected_system_version": expected_system_version,
        "profile_path": expected_profile_path,
        "profile_git_blob_sha": expected_profile_blob,
        "middleware_commit": expected_middleware_commit,
    }
    for key, expected in expected_target.items():
        if target.get(key) != expected:
            raise RuntimeError(
                f"GARM exact target profile drifted for {key}: "
                f"{target.get(key)!r} != {expected!r}"
            )
    if control.get("appliance_reference") != EXPECTED_IMAGE:
        raise RuntimeError("GARM appliance identity drifted")
    if control.get("controller_source") != EXPECTED_CONTROLLER_SOURCE:
        raise RuntimeError("GARM controller source identity drifted")
    if control.get("provider_source") != EXPECTED_PROVIDER_SOURCE:
        raise RuntimeError("TrueNAS provider source identity drifted")
    if control.get("private_secrets_captured") is not False:
        raise RuntimeError("control does not assert private_secrets_captured=false")
    if control.get("fixture_secret_values_retained") is not False:
        raise RuntimeError("control retained fixture secret values")
    if control.get("github_credentials_present") is not False:
        raise RuntimeError("control claims GitHub credentials are present")

    runtime = control.get("runtime") or {}
    if runtime.get("app_name") != EXPECTED_APP_NAME:
        raise RuntimeError("GARM app name drifted")
    if runtime.get("config_root") != EXPECTED_CONFIG_DIR:
        raise RuntimeError("GARM config root drifted")
    if int(runtime.get("host_port") or 0) != 30880:
        raise RuntimeError("GARM guest service port drifted")

    if control.get("runtime_compose_sha256") != canonical_sha256(compose):
        raise RuntimeError("GARM runtime Compose identity does not match control")
    if deployment.get("artifact_sha256") != control.get("deployment_artifact_sha256"):
        raise RuntimeError("GARM deployment artifact identity drifted")
    if deployment.get("materialization_identity") != control.get("materialization_identity"):
        raise RuntimeError("GARM materialization identity drifted")

    services = compose.get("services") or {}
    if set(services) != {"garm", "garm-config-seed"}:
        raise RuntimeError("unexpected GARM service inventory")
    for name in ("garm", "garm-config-seed"):
        service = services[name]
        if service.get("image") != EXPECTED_IMAGE:
            raise RuntimeError(f"{name} image identity drifted")
        if service.get("privileged") is True:
            raise RuntimeError(f"{name} became privileged")
        if "ALL" not in {str(x).upper() for x in service.get("cap_drop") or []}:
            raise RuntimeError(f"{name} lost cap_drop ALL")
        opts = {str(x).lower().replace(":", "=") for x in service.get("security_opt") or []}
        if not any(x.startswith("no-new-privileges=true") for x in opts):
            raise RuntimeError(f"{name} lost no-new-privileges")

    serialized = json.dumps(compose, sort_keys=True)
    for forbidden in (
        "BEGIN PRIVATE KEY",
        "PRIVATE-QUALIFICATION-FIXTURE",
        "PUBLIC-QUALIFICATION-FIXTURE",
        "ghp_",
        "github_pat_",
    ):
        if forbidden in serialized:
            raise RuntimeError(f"secret-like retained control content: {forbidden}")
    if BOOTSTRAP_PLACEHOLDER not in serialized or TLS_PREFIX not in serialized:
        raise RuntimeError("run-local secret placeholders are absent")
    return control, compose


def build_ephemeral_runtime_compose(compose: dict) -> tuple[dict, dict[str, str]]:
    runtime = copy.deepcopy(compose)
    jwt_secret = secrets.token_urlsafe(36)
    alphabet = string.ascii_letters + string.digits
    db_passphrase = "".join(secrets.choice(alphabet) for _ in range(32))
    with tempfile.TemporaryDirectory(prefix="garm-f0-f5-tls-") as td:
        root = pathlib.Path(td)
        key_path = root / "tls.key"
        cert_path = root / "tls.crt"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=garm-t6.invalid",
                "-addext", "subjectAltName=DNS:garm-t6.invalid,IP:127.0.0.1",
                "-keyout", str(key_path), "-out", str(cert_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        tls_key = key_path.read_text(encoding="utf-8")
        tls_cert = cert_path.read_text(encoding="utf-8")

    bootstrap = f"""[default]
enable_webhook_management = false

[logging]
log_level = "info"

[metrics]
disable_auth = false

[jwt_auth]
secret = "{jwt_secret}"
time_to_live = "1h"

[apiserver]
bind = "0.0.0.0"
port = 8080
use_tls = true

[apiserver.tls]
certificate = "/garm-tls.crt"
key = "/garm-tls.key"

[apiserver.webui]
enable = true

[database]
backend = "sqlite3"
passphrase = "{db_passphrase}"

[database.sqlite3]
db_file = "/etc/garm/garm.db"
"""
    configs = runtime["configs"]
    configs[BOOTSTRAP_CONFIG]["content"] = bootstrap
    configs[TLS_CERT_CONFIG]["content"] = tls_cert
    configs[TLS_KEY_CONFIG]["content"] = tls_key
    return runtime, {
        "jwt_secret_sha256": hashlib.sha256(jwt_secret.encode()).hexdigest(),
        "database_passphrase_sha256": hashlib.sha256(db_passphrase.encode()).hexdigest(),
        "certificate_sha256": hashlib.sha256(tls_cert.encode()).hexdigest(),
    }


def https_ui_probe(port: int, timeout: float = 8.0) -> int:
    context = ssl._create_unverified_context()
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=timeout, context=context)
    try:
        conn.request("GET", "/ui/")
        response = conn.getresponse()
        response.read(4096)
        return int(response.status)
    finally:
        conn.close()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--service-port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--control-dir", type=pathlib.Path, required=True)
    p.add_argument("--foundry-commit", required=True)
    p.add_argument("--target-version", required=True)
    p.add_argument("--expected-system-version", required=True)
    p.add_argument("--expected-middleware-commit", required=True)
    p.add_argument("--expected-profile-path", required=True)
    p.add_argument("--expected-profile-blob", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=240.0)
    a = p.parse_args()

    started = time.time()
    payload = {
        "schema": "truenas-garm-controller-f0-f5/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "f0_f5_complete": False,
        "target_version": a.target_version,
        "expected_version": a.expected_system_version,
        "foundry_commit": a.foundry_commit,
        "app_name": EXPECTED_APP_NAME,
        "appliance": EXPECTED_IMAGE,
        "controller_source": EXPECTED_CONTROLLER_SOURCE,
        "provider_source": EXPECTED_PROVIDER_SOURCE,
        "github_credentials_present": False,
        "github_jit_registration_exercised": False,
        "physical_truenas_mutation": False,
        "capacity_promotion": False,
        "secret_values_recorded": False,
    }
    ws = None
    request_id = 1
    app_owned = False
    dataset_owned = False

    try:
        control, retained_compose = load_control(
            a.control_dir,
            a.foundry_commit,
            a.target_version,
            a.expected_system_version,
            a.expected_middleware_commit,
            a.expected_profile_path,
            a.expected_profile_blob,
        )
        runtime_compose, fingerprints = build_ephemeral_runtime_compose(retained_compose)
        retained_sha = canonical_sha256(retained_compose)
        payload["f0"] = {
            "profile_id": control["target"]["profile_id"],
            "profile_path": control["target"]["profile_path"],
            "profile_git_blob_sha": control["target"]["profile_git_blob_sha"],
            "middleware_commit": control["target"]["middleware_commit"],
            "foundry_ref": control["foundry_ref"],
            "appliance": control["appliance_reference"],
        }
        payload["f1"] = {
            "retained_compose_sha256": retained_sha,
            "deployment_artifact_sha256": control["deployment_artifact_sha256"],
            "materialization_identity": control["materialization_identity"],
            "run_local_secret_fingerprints": fingerprints,
        }

        password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError("DDP connection failed")

        def call(method, params):
            nonlocal request_id
            result = ddp_call(ws, str(request_id), method, params)
            request_id += 1
            return result

        def wait_job(job_id, label):
            if not isinstance(job_id, int):
                raise RuntimeError(f"{label} did not return a job id")
            deadline = time.monotonic() + a.job_timeout
            last = None
            while time.monotonic() < deadline:
                last = call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
                if last and last.get("state") == "SUCCESS":
                    return last
                if last and last.get("state") in {"FAILED", "ABORTED"}:
                    raise RuntimeError(
                        f"{label} job {last.get('state')}: "
                        f"{last.get('error') or last.get('exception')}"
                    )
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS: {last!r}")

        def query_optional(method, filters):
            values = call(method, [filters])
            if not values:
                return None
            if not isinstance(values, list) or len(values) != 1:
                raise RuntimeError(f"{method} cardinality was not exactly one")
            return values[0]

        def app_query():
            return query_optional("app.query", [["id", "=", EXPECTED_APP_NAME]])

        def wait_state(expected):
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = app_query()
                if last and last.get("state") == expected:
                    if expected != "RUNNING":
                        return last
                    details = (last.get("active_workloads") or {}).get("container_details") or []
                    exact = [
                        item for item in details
                        if item.get("service_name") == "garm"
                        and item.get("image") == EXPECTED_IMAGE
                        and item.get("state") == "running"
                    ]
                    if len(exact) == 1:
                        return last
                if last and last.get("state") in {"CRASHED", "ERROR"}:
                    raise RuntimeError(f"GARM app entered {last.get('state')}")
                time.sleep(1)
            raise RuntimeError(f"GARM app did not reach {expected}: {last!r}")

        def assert_persistent_state(label):
            config_meta = call("filesystem.stat", [EXPECTED_CONFIG_PATH])
            db_meta = call("filesystem.stat", [EXPECTED_DB_PATH])
            state = {
                "config_toml_size_positive": int(config_meta.get("size") or 0) > 0,
                "garm_db_size_positive": int(db_meta.get("size") or 0) > 0,
            }
            if not all(state.values()):
                raise RuntimeError(f"{label}: persistent config/db state was empty")
            return state

        def normalized_live_compose():
            return normalize_secret_configs(call("app.config", [EXPECTED_APP_NAME]))

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError("authentication did not return SUCCESS")

        observed_version = call("system.version", [])
        if observed_version != a.expected_system_version:
            raise RuntimeError(
                f"target version drifted: {observed_version!r} != {a.expected_system_version!r}"
            )
        methods = call("core.get_methods", [])
        method_names = set(methods if isinstance(methods, list) else methods.keys())
        missing = sorted(REQUIRED_METHODS - method_names)
        if missing:
            raise RuntimeError(f"required middleware methods missing: {missing}")
        payload["f0"]["system_version"] = observed_version
        payload["f0"]["required_methods_present"] = True

        if app_query() is not None:
            raise RuntimeError("refusing adopted GARM app state")
        if query_optional("pool.dataset.query", [["id", "=", EXPECTED_FIXTURE_DATASET]]) is not None:
            raise RuntimeError("refusing adopted GARM fixture dataset")

        dataset = call("pool.dataset.create", [{
            "name": EXPECTED_FIXTURE_DATASET,
            "type": "FILESYSTEM",
            "share_type": "GENERIC",
            "comments": "SemperSupra disposable GARM F0-F5 fixture",
        }])
        if not isinstance(dataset, dict) or dataset.get("id") != EXPECTED_FIXTURE_DATASET:
            raise RuntimeError("pool.dataset.create did not return exact fixture dataset")
        dataset_owned = True

        mkdir = call("filesystem.mkdir", [{
            "path": EXPECTED_CONFIG_DIR,
            "options": {"mode": "750", "raise_chmod_error": True},
        }])
        if not isinstance(mkdir, dict) or mkdir.get("path") != EXPECTED_CONFIG_DIR:
            raise RuntimeError("filesystem.mkdir did not create exact config directory")

        create_id = call("app.create", [{
            "app_name": EXPECTED_APP_NAME,
            "custom_app": True,
            "custom_compose_config": runtime_compose,
        }])
        wait_job(create_id, "app.create")
        app_owned = True
        app = wait_state("RUNNING")
        if app.get("custom_app") is not True:
            raise RuntimeError("GARM runtime did not materialize as a custom app")
        if canonical_sha256(normalized_live_compose()) != retained_sha:
            raise RuntimeError("F2 secret-normalized app.config does not match retained Compose")
        f2_state = assert_persistent_state("F2")
        ui_status = https_ui_probe(a.service_port, timeout=a.timeout)
        if not 200 <= ui_status < 400:
            raise RuntimeError(f"F2 GARM UI returned HTTP {ui_status}")
        payload["f2"] = {
            "app_running": True,
            "compose_readback_exact": True,
            "persistent_state": f2_state,
            "https_ui_status": ui_status,
        }

        wait_job(call("app.stop", [EXPECTED_APP_NAME]), "app.stop")
        wait_state("STOPPED")
        wait_job(call("app.start", [EXPECTED_APP_NAME]), "app.start")
        wait_state("RUNNING")
        restart_sha = canonical_sha256(normalized_live_compose())
        if restart_sha != retained_sha:
            raise RuntimeError("F3 Compose identity drifted after restart")
        restart_state = assert_persistent_state("F3 restart")

        update_id = call(
            "app.update",
            [EXPECTED_APP_NAME, {"custom_compose_config": runtime_compose}],
        )
        wait_job(update_id, "app.update")
        wait_state("RUNNING")
        wait_job(call("app.redeploy", [EXPECTED_APP_NAME]), "app.redeploy")
        wait_state("RUNNING")
        if canonical_sha256(normalized_live_compose()) != retained_sha:
            raise RuntimeError("F3 Compose identity drifted after update/redeploy")
        redeploy_state = assert_persistent_state("F3 update/redeploy")
        redeploy_status = https_ui_probe(a.service_port, timeout=a.timeout)
        if not 200 <= redeploy_status < 400:
            raise RuntimeError(f"F3 GARM UI returned HTTP {redeploy_status}")
        payload["f3"] = {
            "stop_start_pass": True,
            "update_redeploy_pass": True,
            "compose_identity_preserved": True,
            "restart_persistent_state": restart_state,
            "redeploy_persistent_state": redeploy_state,
            "https_ui_status": redeploy_status,
        }

        second_app = app_query()
        second_action = reconciliation_action(
            (second_app or {}).get("state"),
            normalized_live_compose() if second_app else None,
            retained_compose,
        )
        if second_action != "NOOP":
            raise RuntimeError(f"F4 second plan was {second_action}, expected NOOP")
        payload["f4"] = {
            "second_plan_action": second_action,
            "inflight_policy": "WAIT",
            "ambiguous_policy": "FAIL_CLOSED",
        }

        retained_before = query_optional(
            "pool.dataset.query", [["id", "=", EXPECTED_FIXTURE_DATASET]]
        )
        if retained_before is None:
            raise RuntimeError("F5 fixture dataset absent before retain-data delete")
        wait_job(call("app.delete", [EXPECTED_APP_NAME, {
            "remove_images": False,
            "remove_ix_volumes": False,
            "force_remove_custom_app": False,
        }]), "retain-data app.delete")
        app_owned = False
        if app_query() is not None:
            raise RuntimeError("F5 app remained after retain-data delete")
        if query_optional(
            "pool.dataset.query", [["id", "=", EXPECTED_FIXTURE_DATASET]]
        ) is None:
            raise RuntimeError("F5 external fixture dataset was not retained")
        assert_persistent_state("F5 retained-data")

        wait_job(call("app.create", [{
            "app_name": EXPECTED_APP_NAME,
            "custom_app": True,
            "custom_compose_config": runtime_compose,
        }]), "reinstall app.create")
        app_owned = True
        reinstall_app = wait_state("RUNNING")
        if canonical_sha256(normalized_live_compose()) != retained_sha:
            raise RuntimeError("F5 reinstall app.config drifted")
        reinstall_state = assert_persistent_state("F5 reinstall")
        reinstall_status = https_ui_probe(a.service_port, timeout=a.timeout)
        if not 200 <= reinstall_status < 400:
            raise RuntimeError(f"F5 reinstalled GARM UI returned HTTP {reinstall_status}")
        post_reinstall_action = reconciliation_action(
            reinstall_app.get("state"),
            normalized_live_compose(),
            retained_compose,
        )
        if post_reinstall_action != "NOOP":
            raise RuntimeError(
                f"F5 post-reinstall plan was {post_reinstall_action}, expected NOOP"
            )
        payload["f5"] = {
            "external_dataset_retained_across_app_delete": True,
            "persistent_state_after_reinstall": reinstall_state,
            "https_ui_status": reinstall_status,
            "post_reinstall_action": post_reinstall_action,
        }

        wait_job(call("app.delete", [EXPECTED_APP_NAME, {
            "remove_images": False,
            "remove_ix_volumes": False,
            "force_remove_custom_app": False,
        }]), "final app.delete")
        app_owned = False
        deleted = call(
            "pool.dataset.delete",
            [EXPECTED_FIXTURE_DATASET, {"recursive": True, "force": False}],
        )
        if deleted is not True:
            raise RuntimeError("final pool.dataset.delete did not return true")
        dataset_owned = False
        if app_query() is not None:
            raise RuntimeError("final GARM app residue remains")
        if query_optional(
            "pool.dataset.query", [["id", "=", EXPECTED_FIXTURE_DATASET]]
        ) is not None:
            raise RuntimeError("final GARM fixture dataset residue remains")
        mountpoint_absent = False
        try:
            call("filesystem.stat", [EXPECTED_FIXTURE_ROOT])
        except RuntimeError:
            mountpoint_absent = True
        if not mountpoint_absent:
            raise RuntimeError("final GARM fixture mountpoint residue remains")

        payload["cleanup"] = {
            "app_absent": True,
            "fixture_dataset_absent": True,
            "fixture_mountpoint_absent": True,
            "zero_residue": True,
        }
        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["f0_f5_complete"] = True
        payload["detail"] = (
            "exact-target Foundry GARM controller completed F0-F5: exact "
            "profile/materialization identity, create/readback, product health and persistent "
            "state, stop/start/update/redeploy, second-plan NOOP with fail-closed reconciliation, "
            "retain-data delete/reinstall/post-reinstall NOOP, and final zero-residue cleanup"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
        cleanup = {"attempted": bool(app_owned or dataset_owned), "errors": []}
        if ws is not None:
            if app_owned:
                try:
                    current = query_optional("app.query", [["id", "=", EXPECTED_APP_NAME]])
                    if current is not None:
                        wait_job(call("app.delete", [EXPECTED_APP_NAME, {
                            "remove_images": False,
                            "remove_ix_volumes": False,
                            "force_remove_custom_app": False,
                        }]), "failure cleanup app.delete")
                    cleanup["app_absent"] = (
                        query_optional("app.query", [["id", "=", EXPECTED_APP_NAME]])
                        is None
                    )
                except Exception as cleanup_exc:
                    cleanup["errors"].append(
                        f"app: {type(cleanup_exc).__name__}: {cleanup_exc}"
                    )
            if dataset_owned:
                try:
                    current = query_optional(
                        "pool.dataset.query", [["id", "=", EXPECTED_FIXTURE_DATASET]]
                    )
                    if current is not None:
                        deleted = call(
                            "pool.dataset.delete",
                            [EXPECTED_FIXTURE_DATASET, {"recursive": True, "force": False}],
                        )
                        if deleted is not True:
                            raise RuntimeError("cleanup dataset delete did not return true")
                    cleanup["fixture_dataset_absent"] = (
                        query_optional(
                            "pool.dataset.query",
                            [["id", "=", EXPECTED_FIXTURE_DATASET]],
                        )
                        is None
                    )
                except Exception as cleanup_exc:
                    cleanup["errors"].append(
                        f"dataset: {type(cleanup_exc).__name__}: {cleanup_exc}"
                    )
        cleanup["zero_residue"] = (
            cleanup["attempted"]
            and not cleanup["errors"]
            and (cleanup.get("app_absent", not app_owned) is True)
            and (cleanup.get("fixture_dataset_absent", not dataset_owned) is True)
        )
        payload["cleanup"] = cleanup
        payload["cleanup_needed"] = cleanup["attempted"] and not cleanup["zero_residue"]
    finally:
        if ws is not None:
            ws.close()

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
