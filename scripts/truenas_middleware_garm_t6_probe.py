#!/usr/bin/env python3
"""TrueNAS T6 oracle for the exact Foundry-exported GARM controller control."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_FOUNDRY_REF = "7fd0d2474248b61cf8e290fc80f40b761cea5e98"
EXPECTED_SCHEMA = "semper-supra.garm-truenas-t6-control/1"
EXPECTED_APP_NAME = "rdte-t6-garm"
EXPECTED_APPLIANCE = (
    "ghcr.io/sempersupra/garm-appliance@"
    "sha256:1af67841ddd4589e3798dcda8be49230565c849d07ab57fd05899432dcdabca9"
)
EXPECTED_DATASET = "rdtepool/garm-t6"
EXPECTED_ROOT = "/mnt/rdtepool/garm-t6"
EXPECTED_CONFIG_ROOT = "/mnt/rdtepool/garm-t6/config"
BOOTSTRAP_CONFIG = "garm-initial-config"
TLS_CERT_CONFIG = "garm-tls-certificate"
TLS_KEY_CONFIG = "garm-tls-private-key"


def canonical_sha256(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def load_json(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path.name} must contain a JSON object")
    return value


def load_control(directory: pathlib.Path) -> tuple[dict, dict]:
    control = load_json(directory / "control.json")
    compose = load_json(directory / "compose.json")
    if control.get("schema") != EXPECTED_SCHEMA:
        raise RuntimeError("unexpected GARM T6 control schema")
    if control.get("foundry_ref") != EXPECTED_FOUNDRY_REF:
        raise RuntimeError("Foundry source ref drifted")
    if control.get("appliance_reference") != EXPECTED_APPLIANCE:
        raise RuntimeError("GARM appliance identity drifted")
    if control.get("private_secrets_captured") is not False:
        raise RuntimeError("control did not assert private_secrets_captured=false")
    if control.get("fixture_secret_values_retained") is not False:
        raise RuntimeError("control retained bootstrap fixture values")
    if control.get("github_credentials_present") is not False:
        raise RuntimeError("control unexpectedly contains GitHub credentials")
    runtime = control.get("runtime") or {}
    if runtime.get("app_name") != EXPECTED_APP_NAME:
        raise RuntimeError("runtime app name drifted")
    if runtime.get("config_root") != EXPECTED_CONFIG_ROOT:
        raise RuntimeError("runtime config root drifted")
    if canonical_sha256(compose) != control.get("runtime_compose_sha256"):
        raise RuntimeError("runtime Compose identity does not match control")

    configs = compose.get("configs") or {}
    expected = {
        BOOTSTRAP_CONFIG: "__EPHEMERAL_NESTED_GARM_CONFIG__",
        TLS_CERT_CONFIG: f"__EPHEMERAL_NESTED_TLS__:{TLS_CERT_CONFIG}",
        TLS_KEY_CONFIG: f"__EPHEMERAL_NESTED_TLS__:{TLS_KEY_CONFIG}",
    }
    for name, placeholder in expected.items():
        if (configs.get(name) or {}).get("content") != placeholder:
            raise RuntimeError(f"retained {name} is not the expected placeholder")
    if set((compose.get("services") or {}).keys()) != {"garm", "garm-config-seed"}:
        raise RuntimeError("unexpected GARM service inventory")
    return control, compose


def generate_tls() -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="garm-t6-tls-") as td:
        cert = pathlib.Path(td) / "cert.pem"
        key = pathlib.Path(td) / "key.pem"
        cp = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=garm-t6.invalid",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if cp.returncode:
            raise RuntimeError("openssl failed to create run-local TLS material")
        return cert.read_text(encoding="utf-8"), key.read_text(encoding="utf-8")


def runtime_compose(template: dict) -> dict:
    result = copy.deepcopy(template)
    cert, key = generate_tls()
    jwt_secret = secrets.token_hex(24)
    database_passphrase = secrets.token_hex(16)
    bootstrap = f"""[default]
enable_webhook_management = true

[logging]
log_level = "info"

[metrics]
disable_auth = false

[jwt_auth]
secret = "{jwt_secret}"
time_to_live = "8760h"

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
passphrase = "{database_passphrase}"

[database.sqlite3]
db_file = "/etc/garm/garm.db"
"""
    configs = result["configs"]
    configs[BOOTSTRAP_CONFIG]["content"] = bootstrap
    configs[TLS_CERT_CONFIG]["content"] = cert
    configs[TLS_KEY_CONFIG]["content"] = key
    return result


def sanitize_compose(value: dict) -> dict:
    result = copy.deepcopy(value)
    configs = result.get("configs") or {}
    replacements = {
        BOOTSTRAP_CONFIG: "__EPHEMERAL_NESTED_GARM_CONFIG__",
        TLS_CERT_CONFIG: f"__EPHEMERAL_NESTED_TLS__:{TLS_CERT_CONFIG}",
        TLS_KEY_CONFIG: f"__EPHEMERAL_NESTED_TLS__:{TLS_KEY_CONFIG}",
    }
    for name, placeholder in replacements.items():
        item = configs.get(name)
        if not isinstance(item, dict) or "content" not in item:
            raise RuntimeError(f"read-back missing secret-bearing config {name}")
        item["content"] = placeholder
    return result


def https_probe(host: str, port: int, timeout: float) -> bool:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(
            f"https://{host}:{port}/ui/",
            timeout=timeout,
            context=context,
        ) as response:
            return 200 <= response.status < 400
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--service-port", type=int, required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--control-dir", type=pathlib.Path, required=True)
    parser.add_argument("--foundry-commit", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--job-timeout", type=float, default=300.0)
    parser.add_argument("--state-timeout", type=float, default=240.0)
    args = parser.parse_args()

    started = time.time()
    payload = {
        "schema": "truenas-garm-foundry-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": EXPECTED_VERSION,
        "foundry_commit": args.foundry_commit,
        "app_name": EXPECTED_APP_NAME,
        "appliance_reference": EXPECTED_APPLIANCE,
        "secret_values_recorded": False,
        "github_credentials_present": False,
        "github_jit_registration": "NOT_EXERCISED",
        "private_workload": "NOT_EXERCISED",
    }
    ws = None
    created_app = False
    created_dataset = False
    request_id = 1
    try:
        if args.foundry_commit != EXPECTED_FOUNDRY_REF:
            raise RuntimeError("requested Foundry commit does not match admitted export")
        control, template = load_control(args.control_dir)
        desired = runtime_compose(template)
        expected_sanitized_sha = control["runtime_compose_sha256"]

        password = pathlib.Path(args.password_file).read_text(encoding="utf-8").strip()
        ws = WebSocket(args.host, args.port, timeout=args.timeout, tls=args.tls)
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
            deadline = time.monotonic() + args.job_timeout
            while time.monotonic() < deadline:
                last = call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
                if last and last.get("state") == "SUCCESS":
                    return last
                if last and last.get("state") in {"FAILED", "ABORTED"}:
                    raise RuntimeError(f"{label} job {last.get('state')}")
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS")

        def wait_app_state(expected):
            deadline = time.monotonic() + args.state_timeout
            while time.monotonic() < deadline:
                last = call("app.query", [[["id", "=", EXPECTED_APP_NAME]], {"get": True}])
                if last and last.get("state") == expected:
                    return last
                if last and last.get("state") in {"CRASHED", "ERROR"}:
                    raise RuntimeError(f"GARM entered {last.get('state')}")
                time.sleep(1)
            raise RuntimeError(f"GARM did not reach {expected}")

        auth = call(
            "auth.login_ex",
            [{
                "mechanism": "PASSWORD_PLAIN",
                "username": "truenas_admin",
                "password": password,
            }],
        )
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError("authentication did not return SUCCESS")
        payload["system_version"] = call("system.version", [])
        if payload["system_version"] != EXPECTED_VERSION:
            raise RuntimeError("target version drifted")

        if call("app.query", [[["id", "=", EXPECTED_APP_NAME]]]):
            raise RuntimeError("refusing adopted GARM app state")
        if call("pool.dataset.query", [[["id", "=", EXPECTED_DATASET]]]):
            raise RuntimeError("refusing adopted GARM fixture dataset")

        dataset = call(
            "pool.dataset.create",
            [{
                "name": EXPECTED_DATASET,
                "type": "FILESYSTEM",
                "share_type": "GENERIC",
                "comments": "SemperSupra disposable GARM T6 fixture",
            }],
        )
        if not isinstance(dataset, dict) or dataset.get("id") != EXPECTED_DATASET:
            raise RuntimeError("pool.dataset.create did not return exact GARM dataset")
        created_dataset = True

        made = call(
            "filesystem.mkdir",
            [{
                "path": EXPECTED_CONFIG_ROOT,
                "options": {"mode": "700", "raise_chmod_error": True},
            }],
        )
        if not isinstance(made, dict) or made.get("path") != EXPECTED_CONFIG_ROOT:
            raise RuntimeError("filesystem.mkdir did not create exact GARM config root")
        if (int(made.get("mode", 0)) & 0o777) != 0o700:
            raise RuntimeError("GARM config root mode mismatch")

        create_id = call(
            "app.create",
            [{
                "app_name": EXPECTED_APP_NAME,
                "custom_app": True,
                "custom_compose_config": desired,
            }],
        )
        if not isinstance(create_id, int):
            raise RuntimeError("app.create did not return a job id")
        wait_job(create_id, "app.create")
        created_app = True

        app = wait_app_state("RUNNING")
        details = (app.get("active_workloads") or {}).get("container_details") or []
        running = [
            item
            for item in details
            if item.get("service_name") == "garm"
            and item.get("image") == EXPECTED_APPLIANCE
            and item.get("state") == "running"
        ]
        if len(running) != 1:
            raise RuntimeError("running GARM container identity mismatch")

        sanitized = sanitize_compose(call("app.config", [EXPECTED_APP_NAME]))
        readback_sha = canonical_sha256(sanitized)
        if readback_sha != expected_sanitized_sha:
            raise RuntimeError("sanitized app.config read-back differs from Foundry control")

        config_stat = call("filesystem.stat", [f"{EXPECTED_CONFIG_ROOT}/config.toml"])
        db_stat = call("filesystem.stat", [f"{EXPECTED_CONFIG_ROOT}/garm.db"])
        if int(config_stat.get("size", 0)) <= 0 or int(db_stat.get("size", 0)) <= 0:
            raise RuntimeError("GARM persistent config/database was not materialized")

        deadline = time.monotonic() + args.state_timeout
        healthy = False
        while time.monotonic() < deadline:
            healthy = https_probe(args.host, args.service_port, args.timeout)
            if healthy:
                break
            time.sleep(1)
        if not healthy:
            raise RuntimeError("GARM HTTPS /ui/ did not become reachable")

        stop_id = call("app.stop", [EXPECTED_APP_NAME])
        wait_job(stop_id, "app.stop")
        wait_app_state("STOPPED")
        start_id = call("app.start", [EXPECTED_APP_NAME])
        wait_job(start_id, "app.start")
        wait_app_state("RUNNING")

        deadline = time.monotonic() + args.state_timeout
        restart_healthy = False
        while time.monotonic() < deadline:
            restart_healthy = https_probe(args.host, args.service_port, args.timeout)
            if restart_healthy:
                break
            time.sleep(1)
        if not restart_healthy:
            raise RuntimeError("GARM HTTPS /ui/ did not recover after stop/start")

        second_sha = canonical_sha256(
            sanitize_compose(call("app.config", [EXPECTED_APP_NAME]))
        )
        if second_sha != expected_sanitized_sha:
            raise RuntimeError("sanitized GARM Compose identity drifted after restart")
        second_config = call("filesystem.stat", [f"{EXPECTED_CONFIG_ROOT}/config.toml"])
        second_db = call("filesystem.stat", [f"{EXPECTED_CONFIG_ROOT}/garm.db"])
        if int(second_config.get("size", 0)) <= 0 or int(second_db.get("size", 0)) <= 0:
            raise RuntimeError("GARM persistent state did not survive restart")

        delete_id = call(
            "app.delete",
            [EXPECTED_APP_NAME, {
                "remove_images": False,
                "remove_ix_volumes": False,
                "force_remove_custom_app": False,
            }],
        )
        wait_job(delete_id, "app.delete")
        created_app = False
        if call("app.query", [[["id", "=", EXPECTED_APP_NAME]]]):
            raise RuntimeError("GARM app remains after delete")

        deleted = call(
            "pool.dataset.delete",
            [EXPECTED_DATASET, {"recursive": True, "force": False}],
        )
        if deleted is not True:
            raise RuntimeError("pool.dataset.delete did not return true")
        created_dataset = False
        if call("pool.dataset.query", [[["id", "=", EXPECTED_DATASET]]]):
            raise RuntimeError("GARM fixture dataset remains after delete")

        root_absent = False
        try:
            call("filesystem.stat", [EXPECTED_ROOT])
        except RuntimeError:
            root_absent = True
        if not root_absent:
            raise RuntimeError("GARM fixture mountpoint remains after dataset delete")

        payload["materialization"] = {
            "runtime_compose_sha256": expected_sanitized_sha,
            "sanitized_readback_sha256": readback_sha,
            "sanitized_restart_readback_sha256": second_sha,
            "persistent_config_nonempty": True,
            "persistent_database_nonempty": True,
        }
        payload["runtime"] = {
            "state": "RUNNING",
            "custom_app": True,
            "container_image_exact": True,
            "https_ui": healthy,
            "restart_https_ui": restart_healthy,
            "restart_compose_identity_preserved": True,
            "restart_persistent_state_preserved": True,
        }
        payload["cleanup"] = {
            "app_absent": True,
            "fixture_dataset_absent": True,
            "fixture_mountpoint_absent": True,
            "zero_residue": True,
        }
        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "exact Foundry-exported GARM controller materialized on real nested TrueNAS; "
            "sanitized config read-back, HTTPS health, persistent-state restart, and "
            "delete/zero-residue passed; GitHub JIT/private workload intentionally not exercised"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
        payload["cleanup_needed"] = {
            "app": created_app,
            "dataset": created_dataset,
        }
    finally:
        if ws is not None:
            ws.close()

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(args.out).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
