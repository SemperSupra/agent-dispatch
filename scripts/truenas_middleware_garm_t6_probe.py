#!/usr/bin/env python3
"""Bounded GARM controller Foundry T6 oracle on disposable TrueNAS."""
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

SCHEMA = "semper-supra.garm-truenas-t6-control/1"
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


def canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_json(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain an object")
    return value


def normalize_secret_configs(compose: dict) -> dict:
    normalized = copy.deepcopy(compose)
    configs = normalized.get("configs") or {}
    if BOOTSTRAP_CONFIG not in configs or TLS_CERT_CONFIG not in configs or TLS_KEY_CONFIG not in configs:
        raise RuntimeError("GARM secret-bearing config inventory drifted")
    configs[BOOTSTRAP_CONFIG]["content"] = BOOTSTRAP_PLACEHOLDER
    configs[TLS_CERT_CONFIG]["content"] = TLS_PREFIX + TLS_CERT_CONFIG
    configs[TLS_KEY_CONFIG]["content"] = TLS_PREFIX + TLS_KEY_CONFIG
    return normalized


def load_control(directory: pathlib.Path, foundry_commit: str) -> tuple[dict, dict]:
    control = load_json(directory / "control.json")
    compose = load_json(directory / "compose.json")
    deployment = load_json(directory / "deployment.json")

    if control.get("schema") != SCHEMA:
        raise RuntimeError("unexpected GARM T6 control schema")
    if control.get("foundry_ref") != foundry_commit:
        raise RuntimeError("Foundry source ref drifted")
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
        raise RuntimeError("GARM T6 app name drifted")
    if runtime.get("config_root") != EXPECTED_CONFIG_DIR:
        raise RuntimeError("GARM T6 config root drifted")
    if int(runtime.get("host_port") or 0) != 30880:
        raise RuntimeError("GARM T6 guest service port drifted")
    if runtime.get("bootstrap_replacement") != BOOTSTRAP_CONFIG:
        raise RuntimeError("GARM bootstrap replacement contract drifted")

    if control.get("runtime_compose_sha256") != canonical_sha256(compose):
        raise RuntimeError("GARM runtime Compose identity does not match control")
    if deployment.get("artifact_sha256") != control.get("deployment_artifact_sha256"):
        raise RuntimeError("GARM deployment artifact identity drifted")
    if deployment.get("materialization_identity") != control.get("materialization_identity"):
        raise RuntimeError("GARM materialization identity drifted")

    services = compose.get("services") or {}
    if set(services) != {"garm", "garm-config-seed"}:
        raise RuntimeError("unexpected GARM T6 service inventory")
    for name in ("garm", "garm-config-seed"):
        service = services[name]
        if service.get("image") != EXPECTED_IMAGE:
            raise RuntimeError(f"{name} image identity drifted")
        if service.get("privileged") is True:
            raise RuntimeError(f"{name} became privileged")
        if "ALL" not in {str(x).upper() for x in service.get("cap_drop") or []}:
            raise RuntimeError(f"{name} lost cap_drop ALL")
        options = {str(x).lower().replace(":", "=") for x in service.get("security_opt") or []}
        if not any(x.startswith("no-new-privileges=true") for x in options):
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

    with tempfile.TemporaryDirectory(prefix="garm-t6-tls-") as td:
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
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=240.0)
    a = p.parse_args()

    started = time.time()
    payload = {
        "schema": "truenas-garm-foundry-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": f"TrueNAS-{a.target_version}",
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
    created_app = False
    created_dataset = False

    try:
        control, retained_compose = load_control(a.control_dir, a.foundry_commit)
        runtime_compose, secret_fingerprints = build_ephemeral_runtime_compose(retained_compose)
        retained_sha = canonical_sha256(retained_compose)
        payload["materialization"] = {
            "schema": control["schema"],
            "foundry_ref": control["foundry_ref"],
            "retained_compose_sha256": retained_sha,
            "deployment_artifact_sha256": control["deployment_artifact_sha256"],
            "materialization_identity": control["materialization_identity"],
            "run_local_secret_fingerprints": secret_fingerprints,
            "secret_values_recorded": False,
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
            deadline = time.monotonic() + a.job_timeout
            last = None
            while time.monotonic() < deadline:
                last = call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
                if last and last.get("state") == "SUCCESS":
                    return last
                if last and last.get("state") in {"FAILED", "ABORTED"}:
                    raise RuntimeError(f"{label} job {last.get('state')}")
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS")

        def app_query():
            return call("app.query", [[["id", "=", EXPECTED_APP_NAME]], {"get": True}])

        def wait_running():
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = app_query()
                if last:
                    if last.get("state") in {"CRASHED", "ERROR"}:
                        raise RuntimeError(f"GARM app entered {last.get('state')}")
                    details = (last.get("active_workloads") or {}).get("container_details") or []
                    controllers = [
                        item for item in details
                        if item.get("service_name") == "garm"
                        and item.get("image") == EXPECTED_IMAGE
                        and item.get("state") == "running"
                    ]
                    if last.get("state") == "RUNNING" and len(controllers) == 1:
                        return last
                time.sleep(1)
            raise RuntimeError(f"GARM controller did not reach RUNNING: {last!r}")

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError("authentication did not return SUCCESS")

        payload["system_version"] = call("system.version", [])
        if payload["system_version"] != payload["expected_version"]:
            raise RuntimeError("target version drifted")

        if call("app.query", [[["id", "=", EXPECTED_APP_NAME]]]):
            raise RuntimeError("refusing adopted GARM app state")
        if call("pool.dataset.query", [[["id", "=", EXPECTED_FIXTURE_DATASET]]]):
            raise RuntimeError("refusing adopted GARM fixture dataset")

        dataset = call("pool.dataset.create", [{
            "name": EXPECTED_FIXTURE_DATASET,
            "type": "FILESYSTEM",
            "share_type": "GENERIC",
            "comments": "SemperSupra disposable GARM T6 fixture",
        }])
        if not isinstance(dataset, dict) or dataset.get("id") != EXPECTED_FIXTURE_DATASET:
            raise RuntimeError("pool.dataset.create did not return exact GARM fixture dataset")
        created_dataset = True

        mkdir = call("filesystem.mkdir", [{
            "path": EXPECTED_CONFIG_DIR,
            "options": {"mode": "750", "raise_chmod_error": True},
        }])
        if not isinstance(mkdir, dict) or mkdir.get("path") != EXPECTED_CONFIG_DIR:
            raise RuntimeError("filesystem.mkdir did not create exact GARM config directory")
        payload["fixture_storage"] = {
            "dataset": EXPECTED_FIXTURE_DATASET,
            "config_dir": EXPECTED_CONFIG_DIR,
            "content_recorded": False,
        }

        create_id = call("app.create", [{
            "app_name": EXPECTED_APP_NAME,
            "custom_app": True,
            "custom_compose_config": runtime_compose,
        }])
        if not isinstance(create_id, int):
            raise RuntimeError("app.create did not return a job id")
        wait_job(create_id, "app.create")
        created_app = True

        app = wait_running()
        details = (app.get("active_workloads") or {}).get("container_details") or []
        payload["runtime"] = {
            "state": app.get("state"),
            "custom_app": app.get("custom_app"),
            "controller_running_exact_image": any(
                item.get("service_name") == "garm"
                and item.get("image") == EXPECTED_IMAGE
                and item.get("state") == "running"
                for item in details
            ),
            "container_states": sorted({
                f"{item.get('service_name')}:{item.get('state')}"
                for item in details
                if isinstance(item, dict)
            }),
        }
        if app.get("custom_app") is not True:
            raise RuntimeError("GARM runtime did not materialize as a custom app")

        readback = call("app.config", [EXPECTED_APP_NAME])
        normalized_readback = normalize_secret_configs(readback)
        readback_sha = canonical_sha256(normalized_readback)
        if readback_sha != retained_sha:
            raise RuntimeError("secret-normalized app.config read-back does not match retained Foundry Compose")
        payload["runtime"]["secret_normalized_compose_readback_sha256"] = readback_sha

        config_meta = call("filesystem.stat", [EXPECTED_CONFIG_PATH])
        db_meta = call("filesystem.stat", [EXPECTED_DB_PATH])
        payload["persistent_state"] = {
            "config_toml": {
                "path": EXPECTED_CONFIG_PATH,
                "type": config_meta.get("type"),
                "size_positive": int(config_meta.get("size") or 0) > 0,
            },
            "garm_db": {
                "path": EXPECTED_DB_PATH,
                "type": db_meta.get("type"),
                "size_positive": int(db_meta.get("size") or 0) > 0,
            },
            "raw_content_recorded": False,
        }
        if not payload["persistent_state"]["config_toml"]["size_positive"]:
            raise RuntimeError("persistent config.toml is empty")
        if not payload["persistent_state"]["garm_db"]["size_positive"]:
            raise RuntimeError("persistent garm.db is empty")

        status = https_ui_probe(a.service_port, timeout=a.timeout)
        if status < 200 or status >= 400:
            raise RuntimeError(f"GARM external /ui/ probe returned HTTP {status}")
        payload["runtime"]["external_https_ui_status"] = status

        stop_id = call("app.stop", [EXPECTED_APP_NAME])
        wait_job(stop_id, "app.stop")
        stopped = app_query()
        if not stopped or stopped.get("state") != "STOPPED":
            raise RuntimeError("GARM app did not reach STOPPED")

        start_id = call("app.start", [EXPECTED_APP_NAME])
        wait_job(start_id, "app.start")
        wait_running()

        restart_readback = normalize_secret_configs(call("app.config", [EXPECTED_APP_NAME]))
        if canonical_sha256(restart_readback) != retained_sha:
            raise RuntimeError("GARM secret-normalized Compose identity drifted after restart")
        restart_status = https_ui_probe(a.service_port, timeout=a.timeout)
        if restart_status < 200 or restart_status >= 400:
            raise RuntimeError(f"GARM external /ui/ restart probe returned HTTP {restart_status}")
        payload["runtime"]["restart_compose_identity_preserved"] = True
        payload["runtime"]["restart_https_ui_status"] = restart_status

        delete_id = call("app.delete", [EXPECTED_APP_NAME, {
            "remove_images": False,
            "remove_ix_volumes": False,
            "force_remove_custom_app": False,
        }])
        wait_job(delete_id, "app.delete")
        created_app = False
        if call("app.query", [[["id", "=", EXPECTED_APP_NAME]]]):
            raise RuntimeError("GARM app remains after delete")

        deleted = call("pool.dataset.delete", [
            EXPECTED_FIXTURE_DATASET,
            {"recursive": True, "force": False},
        ])
        if deleted is not True:
            raise RuntimeError("pool.dataset.delete did not return true")
        created_dataset = False
        if call("pool.dataset.query", [[["id", "=", EXPECTED_FIXTURE_DATASET]]]):
            raise RuntimeError("GARM fixture dataset remains after delete")

        mountpoint_absent = False
        try:
            call("filesystem.stat", [EXPECTED_FIXTURE_ROOT])
        except RuntimeError:
            mountpoint_absent = True
        if not mountpoint_absent:
            raise RuntimeError("GARM fixture mountpoint remains after dataset delete")

        payload["cleanup"] = {
            "app_absent": True,
            "fixture_dataset_absent": True,
            "fixture_mountpoint_absent": True,
            "zero_residue": True,
        }
        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "exact Foundry-exported GARM controller App realized on real disposable TrueNAS; "
            "exact appliance and secret-normalized config read-back, persistent controller state, "
            "external HTTPS UI, restart persistence, and delete/zero-residue all passed; "
            "GitHub credentials/JIT registration intentionally not exercised"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
        payload["cleanup_needed"] = {
            "app": created_app,
            "fixture_dataset": created_dataset,
        }
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
