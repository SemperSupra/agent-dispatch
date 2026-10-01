#!/usr/bin/env python3
"""TrueNAS T6 oracle for the exact Foundry-exported LiteLLM control."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import pathlib
import ssl
import time
import urllib.error
import urllib.request

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_FOUNDRY_REF = "4ba12f4a870f9af8a667056f1e2cc32f80f8e2ba"
EXPECTED_SCHEMA = "semper-supra.litellm-truenas-t6-control/1"
EXPECTED_APPLIANCE = (
    "ghcr.io/sempersupra/litellm-appliance@"
    "sha256:225c899db85865929f6099d3e1fe27097cafaed5af823fa397e75e1eb6ec51ac"
)
EXPECTED_APPLIANCE_DIGEST = (
    "sha256:225c899db85865929f6099d3e1fe27097cafaed5af823fa397e75e1eb6ec51ac"
)
EXPECTED_TRUENAS_APPS_COMMIT = "4df7498747aad81b1049135539c65c383e42df95"
EXPECTED_LIBRARY_VERSION = "2.3.11"
EXPECTED_LIBRARY_HASH = "874636814efb275e5276ea9d709b7cd665fed42bb1d50328e853d9253a2e1229"
EXPECTED_APP_NAME = "rdte-t6-litellm"
EXPECTED_GUEST_PORT = 30401
EXPECTED_FIXTURE_DATASET = "rdtepool/litellm-t6"
EXPECTED_FIXTURE_ROOT = "/mnt/rdtepool/litellm-t6"
EXPECTED_CONFIG_DIR = "/mnt/rdtepool/litellm-t6/config"
EXPECTED_SECRET_DIR = "/mnt/rdtepool/litellm-t6/secrets"
EXPECTED_CONFIG_FILE = "proxy_server_config.yaml"
EXPECTED_FIXTURE_SECRET_NAMES = ["TEST_PROVIDER_KEY"]
FIXTURE_SECRET_VALUE = b"rdte-fixture-provider-token\n"


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_json(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path.name} must contain a JSON object")
    return value


def _one_service(compose: dict) -> tuple[str, dict]:
    services = compose.get("services")
    if not isinstance(services, dict) or len(services) != 1:
        raise RuntimeError("expected exactly one rendered LiteLLM service")
    name, service = next(iter(services.items()))
    if not isinstance(service, dict):
        raise RuntimeError("rendered LiteLLM service must be an object")
    return str(name), service


def _one_mount(service: dict, target: str) -> dict:
    matches = [
        value
        for value in service.get("volumes", [])
        if isinstance(value, dict) and value.get("target") == target
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one mount for {target}")
    return matches[0]


def load_control(directory: pathlib.Path):
    control = _load_json(directory / "control.json")
    compose = _load_json(directory / "compose.json")
    config_bytes = (directory / EXPECTED_CONFIG_FILE).read_bytes()

    if control.get("schema") != EXPECTED_SCHEMA:
        raise RuntimeError("unexpected LiteLLM T6 control schema")
    if control.get("foundry_ref") != EXPECTED_FOUNDRY_REF:
        raise RuntimeError("Foundry source ref drifted")
    if control.get("secrets_captured") is not False:
        raise RuntimeError("control bundle does not assert secrets_captured=false")

    candidate = control.get("candidate") or {}
    if candidate.get("appliance_reference") != EXPECTED_APPLIANCE:
        raise RuntimeError("admitted appliance reference drifted")
    if candidate.get("appliance_digest") != EXPECTED_APPLIANCE_DIGEST:
        raise RuntimeError("admitted appliance digest drifted")
    if candidate.get("truenas_apps_commit") != EXPECTED_TRUENAS_APPS_COMMIT:
        raise RuntimeError("TrueNAS Apps source commit drifted")
    if candidate.get("truenas_lib_version") != EXPECTED_LIBRARY_VERSION:
        raise RuntimeError("TrueNAS library version drifted")
    if candidate.get("truenas_lib_hash") != EXPECTED_LIBRARY_HASH:
        raise RuntimeError("TrueNAS library hash drifted")

    runtime = control.get("runtime") or {}
    expected_runtime = {
        "app_name": EXPECTED_APP_NAME,
        "guest_port": EXPECTED_GUEST_PORT,
        "config_dir": EXPECTED_CONFIG_DIR,
        "secret_dir": EXPECTED_SECRET_DIR,
        "config_file": EXPECTED_CONFIG_FILE,
        "fixture_secret_names": EXPECTED_FIXTURE_SECRET_NAMES,
    }
    for key, expected in expected_runtime.items():
        if runtime.get(key) != expected:
            raise RuntimeError(f"runtime {key} drifted")

    artifacts = control.get("artifacts") or {}
    if artifacts.get("compose_canonical_sha256") != canonical_sha256(compose):
        raise RuntimeError("rendered Compose identity does not match control")
    if artifacts.get("config_sha256") != sha256_bytes(config_bytes):
        raise RuntimeError("fixture config identity does not match control")

    service_name, service = _one_service(compose)
    if service.get("image") != EXPECTED_APPLIANCE:
        raise RuntimeError("rendered service image drifted")
    config_mount = _one_mount(service, "/config")
    secret_mount = _one_mount(service, "/run/secrets/semper-env")
    for label, mount, source in (
        ("config", config_mount, EXPECTED_CONFIG_DIR),
        ("provider-secret", secret_mount, EXPECTED_SECRET_DIR),
    ):
        if mount.get("source") != source or mount.get("read_only") is not True:
            raise RuntimeError(f"{label} mount drifted")
    if (service.get("environment") or {}).get("SEMPER_SECRET_DIR") != "/run/secrets/semper-env":
        raise RuntimeError("SEMPER_SECRET_DIR drifted")
    if not any(
        isinstance(port, dict)
        and int(port.get("target", -1)) == 4000
        and str(port.get("published")) == str(EXPECTED_GUEST_PORT)
        for port in service.get("ports", [])
    ):
        raise RuntimeError("LiteLLM guest port mapping drifted")

    rendered = json.dumps(compose, sort_keys=True)
    for forbidden in ("OPENROUTER_MANAGEMENT_KEY", "sk-or-mgmt-", ":latest", ":main-latest"):
        if forbidden in rendered:
            raise RuntimeError(f"forbidden rendered content: {forbidden}")

    return control, compose, config_bytes, service_name


def multipart_upload(
    host: str,
    port: int,
    tls: bool,
    username: str,
    password: str,
    remote_path: str,
    content: bytes,
    mode: int,
    timeout: float,
) -> int:
    boundary = "----semper-supra-litellm-t6-boundary"
    data = json.dumps(
        {"method": "filesystem.put", "params": [remote_path, {"append": False, "mode": mode}]},
        separators=(",", ":"),
    )
    chunks = [
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="data"\r\n\r\n',
        data.encode(),
        b"\r\n",
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="file"; filename="payload"\r\n',
        b"Content-Type: application/octet-stream\r\n\r\n",
        content,
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    body = b"".join(chunks)
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {
        "Authorization": f"Basic {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", "/_upload/", body=body, headers=headers)
        response = conn.getresponse()
        payload = response.read()
    finally:
        conn.close()
    if response.status < 200 or response.status >= 300:
        raise RuntimeError(f"filesystem.put upload returned HTTP {response.status}")
    result = json.loads(payload.decode("utf-8"))
    job_id = result.get("job_id")
    if not isinstance(job_id, int):
        raise RuntimeError("filesystem.put upload did not return a job_id")
    return job_id


def health_probe(host: str, port: int, path: str, timeout: float) -> bool:
    try:
        with urllib.request.urlopen(
            f"http://{host}:{port}{path}",
            timeout=timeout,
        ) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True, help="TrueNAS middleware HTTP(S) host-forward port")
    p.add_argument("--service-port", type=int, required=True, help="host-forward port for guest LiteLLM port 30401")
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
        "schema": "truenas-litellm-foundry-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": f"TrueNAS-{a.target_version}",
        "foundry_commit": a.foundry_commit,
        "app_name": EXPECTED_APP_NAME,
        "appliance_reference": EXPECTED_APPLIANCE,
        "fixture_secret_names": EXPECTED_FIXTURE_SECRET_NAMES,
        "secret_values_captured": False,
        "management_credentials_present": False,
    }
    ws = None
    created_app = False
    request_id = 1
    try:
        if a.foundry_commit != EXPECTED_FOUNDRY_REF:
            raise RuntimeError("requested Foundry commit does not match qualified export")
        control, compose, config_bytes, service_name = load_control(a.control_dir)
        compose_sha = canonical_sha256(compose)
        payload["materialization"] = {
            "schema": control["schema"],
            "foundry_ref": control["foundry_ref"],
            "compose_canonical_sha256": compose_sha,
            "config_sha256": sha256_bytes(config_bytes),
            "service_name": service_name,
            "truenas_apps_commit": EXPECTED_TRUENAS_APPS_COMMIT,
            "truenas_lib_version": EXPECTED_LIBRARY_VERSION,
            "truenas_lib_hash": EXPECTED_LIBRARY_HASH,
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

        def wait_app_state(expected):
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = call("app.query", [[["id", "=", EXPECTED_APP_NAME]], {"get": True}])
                if last and last.get("state") == expected:
                    return last
                if last and last.get("state") in {"CRASHED", "ERROR"}:
                    raise RuntimeError(f"LiteLLM entered {last.get('state')}")
                time.sleep(1)
            raise RuntimeError(f"LiteLLM did not reach {expected}")

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

        existing = call("app.query", [[["id", "=", EXPECTED_APP_NAME]]])
        if existing:
            raise RuntimeError("refusing adopted LiteLLM app state")

        existing_dataset = call("pool.dataset.query", [[["id", "=", EXPECTED_FIXTURE_DATASET]]])
        if existing_dataset:
            raise RuntimeError("refusing adopted LiteLLM T6 fixture dataset")

        dataset = call("pool.dataset.create", [{
            "name": EXPECTED_FIXTURE_DATASET,
            "type": "FILESYSTEM",
            "share_type": "GENERIC",
            "comments": "SemperSupra disposable LiteLLM T6 fixture",
        }])
        if not isinstance(dataset, dict) or dataset.get("id") != EXPECTED_FIXTURE_DATASET:
            raise RuntimeError("pool.dataset.create did not return exact T6 dataset identity")

        fixture_dirs = [
            (EXPECTED_CONFIG_DIR, "750"),
            (EXPECTED_SECRET_DIR, "700"),
        ]
        created_dirs = []
        for path, mode in fixture_dirs:
            result = call("filesystem.mkdir", [{
                "path": path,
                "options": {"mode": mode, "raise_chmod_error": True},
            }])
            if not isinstance(result, dict) or result.get("path") != path:
                raise RuntimeError(f"filesystem.mkdir did not create exact path {path}")
            observed_mode = int(result.get("mode", 0)) & 0o777
            if observed_mode != int(mode, 8):
                raise RuntimeError(f"filesystem.mkdir mode mismatch for {path}")
            created_dirs.append({
                "path": path,
                "mode": oct(observed_mode),
            })
        payload["fixture_storage"] = {
            "dataset": EXPECTED_FIXTURE_DATASET,
            "root": EXPECTED_FIXTURE_ROOT,
            "directories": created_dirs,
            "values_recorded": False,
        }

        config_remote = f"{EXPECTED_CONFIG_DIR}/{EXPECTED_CONFIG_FILE}"
        secret_remote = f"{EXPECTED_SECRET_DIR}/TEST_PROVIDER_KEY"
        config_job = multipart_upload(
            a.host, a.port, a.tls, "truenas_admin", password,
            config_remote, config_bytes, 0o640, a.timeout,
        )
        wait_job(config_job, "config filesystem.put")
        secret_job = multipart_upload(
            a.host, a.port, a.tls, "truenas_admin", password,
            secret_remote, FIXTURE_SECRET_VALUE, 0o600, a.timeout,
        )
        wait_job(secret_job, "fixture secret filesystem.put")

        config_stat = call("filesystem.stat", [config_remote])
        secret_stat = call("filesystem.stat", [secret_remote])
        payload["fixture_projection"] = {
            "config_path": config_remote,
            "config_sha256": sha256_bytes(config_bytes),
            "config_mode": oct(int(config_stat.get("mode", 0)) & 0o777),
            "secret_path": secret_remote,
            "secret_names": EXPECTED_FIXTURE_SECRET_NAMES,
            "secret_mode": oct(int(secret_stat.get("mode", 0)) & 0o777),
            "secret_value_recorded": False,
        }
        if (int(secret_stat.get("mode", 0)) & 0o777) != 0o600:
            raise RuntimeError("fixture S1 file mode is not 0600")

        create_id = call("app.create", [{
            "app_name": EXPECTED_APP_NAME,
            "custom_app": True,
            "custom_compose_config": compose,
        }])
        if not isinstance(create_id, int):
            raise RuntimeError("app.create did not return a job id")
        wait_job(create_id, "app.create")
        created_app = True

        app = wait_app_state("RUNNING")
        details = (app.get("active_workloads") or {}).get("container_details") or []
        matching = [
            item for item in details
            if item.get("service_name") == service_name
            and item.get("image") == EXPECTED_APPLIANCE
            and item.get("state") == "running"
        ]
        if len(matching) != 1:
            raise RuntimeError("running container image/service identity mismatch")

        config_readback = call("app.config", [EXPECTED_APP_NAME])
        config_readback_sha = canonical_sha256(config_readback)
        if config_readback_sha != compose_sha:
            raise RuntimeError("app.config read-back does not match exact Foundry Compose")

        live = ready = False
        deadline = time.monotonic() + a.state_timeout
        while time.monotonic() < deadline:
            live = health_probe(a.host, a.service_port, "/health/liveliness", a.timeout)
            ready = health_probe(a.host, a.service_port, "/health/readiness", a.timeout)
            if live and ready:
                break
            time.sleep(1)
        if not (live and ready):
            raise RuntimeError("LiteLLM health endpoints did not pass")

        stop_id = call("app.stop", [EXPECTED_APP_NAME])
        wait_job(stop_id, "app.stop")
        wait_app_state("STOPPED")
        start_id = call("app.start", [EXPECTED_APP_NAME])
        wait_job(start_id, "app.start")
        wait_app_state("RUNNING")

        deadline = time.monotonic() + a.state_timeout
        restart_live = restart_ready = False
        while time.monotonic() < deadline:
            restart_live = health_probe(a.host, a.service_port, "/health/liveliness", a.timeout)
            restart_ready = health_probe(a.host, a.service_port, "/health/readiness", a.timeout)
            if restart_live and restart_ready:
                break
            time.sleep(1)
        if not (restart_live and restart_ready):
            raise RuntimeError("LiteLLM health did not recover after stop/start")

        second_config_sha = canonical_sha256(call("app.config", [EXPECTED_APP_NAME]))
        if second_config_sha != compose_sha:
            raise RuntimeError("Foundry Compose identity drifted after restart")

        delete_id = call("app.delete", [EXPECTED_APP_NAME, {
            "remove_images": False,
            "remove_ix_volumes": False,
            "force_remove_custom_app": False,
        }])
        wait_job(delete_id, "app.delete")
        created_app = False
        remaining = call("app.query", [[["id", "=", EXPECTED_APP_NAME]]])
        if remaining:
            raise RuntimeError("LiteLLM app remains after delete")

        deleted_dataset = call("pool.dataset.delete", [
            EXPECTED_FIXTURE_DATASET,
            {"recursive": True, "force": False},
        ])
        if deleted_dataset is not True:
            raise RuntimeError("pool.dataset.delete did not return true")

        remaining_dataset = call(
            "pool.dataset.query",
            [[["id", "=", EXPECTED_FIXTURE_DATASET]]],
        )
        if remaining_dataset:
            raise RuntimeError("LiteLLM T6 fixture dataset remains after delete")

        root_absent = False
        try:
            call("filesystem.stat", [EXPECTED_FIXTURE_ROOT])
        except RuntimeError:
            root_absent = True
        if not root_absent:
            raise RuntimeError("LiteLLM T6 fixture mountpoint remains after dataset delete")

        payload["cleanup"] = {
            "app_absent": True,
            "fixture_dataset_absent": True,
            "fixture_mountpoint_absent": True,
            "zero_residue": True,
        }

        payload["runtime"] = {
            "state": "RUNNING",
            "custom_app": True,
            "container_image_exact": True,
            "compose_readback_sha256": config_readback_sha,
            "liveliness": live,
            "readiness": ready,
            "restart_liveliness": restart_live,
            "restart_readiness": restart_ready,
            "restart_compose_identity_preserved": True,
            "delete_absent": True,
            "zero_residue": True,
        }
        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "exact Foundry-exported LiteLLM appliance consumed on real TrueNAS software; "
            "S1 fixture projection, exact image/config read-back, health, restart persistence, "
            "and delete/zero-residue all passed"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
        payload["cleanup_needed"] = created_app
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
