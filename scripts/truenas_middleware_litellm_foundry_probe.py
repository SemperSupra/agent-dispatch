#!/usr/bin/env python3
"""TrueNAS T6 oracle for the exact LiteLLM Foundry candidate."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import ssl
import time
import urllib.error
import urllib.request
import uuid

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_FOUNDRY_COMMIT = "5f62da5ba229986879fa4f5d7a53169d0ed80356"
EXPECTED_PRODUCT_HEAD = "f09e7ed495c2bcfff2fa050ec61db268412fa0a9"
EXPECTED_PUBLIC_PROJECTION = "76ed8c35a39aaadcfc69a5c8ca95496bd0e8cf97"
EXPECTED_TRUENAS_APPS_COMMIT = "4df7498747aad81b1049135539c65c383e42df95"
EXPECTED_LIBRARY_VERSION = "2.3.11"
EXPECTED_LIBRARY_HASH = "874636814efb275e5276ea9d709b7cd665fed42bb1d50328e853d9253a2e1229"
EXPECTED_IMAGE = "ghcr.io/sempersupra/litellm-appliance@sha256:225c899db85865929f6099d3e1fe27097cafaed5af823fa397e75e1eb6ec51ac"
EXPECTED_CONFIG_SHA256 = "d9b619992abff31e0ad0dd5537c73a4faecb108a89d323ba873ba991c21cfcd7"
EXPECTED_SECRET_SHA256 = "76f000bbd6cf199852dfd5518a03754ce3662dc3d6db5cb227ecf54c8307c41e"
APP_NAME = "rdte-t6-litellm"
RUNTIME_ROOT = "/mnt/rdtepool/rdte-t6-litellm"
CONFIG_DIR = f"{RUNTIME_ROOT}/config"
SECRET_DIR = f"{RUNTIME_ROOT}/secrets"
CONFIG_PATH = f"{CONFIG_DIR}/proxy_server_config.yaml"
SECRET_NAME = "TEST_PROVIDER_KEY"
SECRET_PATH = f"{SECRET_DIR}/{SECRET_NAME}"
APP_GUEST_PORT = 30400
SYNTHETIC_SECRET_BYTES = b"fixture-provider-token\n"


def canonical_sha256(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mounts(service: dict) -> list[dict]:
    result = []
    for mount in service.get("volumes") or []:
        if isinstance(mount, dict):
            result.append({
                "source": str(mount.get("source") or ""),
                "target": str(mount.get("target") or ""),
                "read_only": bool(mount.get("read_only", False)),
            })
        elif isinstance(mount, str):
            parts = mount.split(":")
            if len(parts) >= 2:
                result.append({
                    "source": parts[0],
                    "target": parts[1],
                    "read_only": len(parts) > 2 and "ro" in parts[2].split(","),
                })
    return result


def require_mount(service: dict, source: str, target: str) -> None:
    matches = [m for m in mounts(service) if m["source"] == source and m["target"] == target]
    if len(matches) != 1 or matches[0]["read_only"] is not True:
        raise RuntimeError(f"expected exactly one read-only mount {source!r} -> {target!r}")


def load_control(directory: pathlib.Path, foundry_commit: str):
    index = json.loads((directory / "index.json").read_text(encoding="utf-8"))
    if index.get("schema") != "semper-supra.litellm-truenas-foundry-control/1":
        raise RuntimeError("unexpected LiteLLM T6 control schema")
    if foundry_commit != EXPECTED_FOUNDRY_COMMIT:
        raise RuntimeError("caller Foundry commit drifted")
    if index.get("foundry", {}).get("commit") != EXPECTED_FOUNDRY_COMMIT:
        raise RuntimeError("Foundry materializer commit drifted")
    if index.get("product_source", {}).get("head") != EXPECTED_PRODUCT_HEAD:
        raise RuntimeError("private product-source head drifted")
    if index.get("public_projection", {}).get("head") != EXPECTED_PUBLIC_PROJECTION:
        raise RuntimeError("public projection head drifted")

    truenas = index.get("truenas_apps") or {}
    if truenas.get("commit") != EXPECTED_TRUENAS_APPS_COMMIT:
        raise RuntimeError("TrueNAS Apps commit drifted")
    if truenas.get("library_version") != EXPECTED_LIBRARY_VERSION:
        raise RuntimeError("TrueNAS library version drifted")
    if truenas.get("library_hash") != EXPECTED_LIBRARY_HASH:
        raise RuntimeError("TrueNAS library hash drifted")

    appliance = index.get("appliance") or {}
    if appliance.get("reference") != EXPECTED_IMAGE:
        raise RuntimeError("admitted LiteLLM appliance identity drifted")

    runtime = index.get("runtime") or {}
    expected_runtime = {
        "app_name": APP_NAME,
        "config_dir": CONFIG_DIR,
        "secret_dir": SECRET_DIR,
        "published_port": APP_GUEST_PORT,
    }
    for key, value in expected_runtime.items():
        if runtime.get(key) != value:
            raise RuntimeError(f"runtime {key} drifted: {runtime.get(key)!r}")

    compose_path = directory / str(index.get("compose_path") or "")
    compose = json.loads(compose_path.read_text(encoding="utf-8"))
    compose.pop("name", None)
    digest = canonical_sha256(compose)
    if digest != index.get("compose_sha256"):
        raise RuntimeError("materialized Compose identity mismatch")
    services = compose.get("services") or {}
    if sorted(services) != ["litellm"]:
        raise RuntimeError(f"unexpected service set: {sorted(services)}")
    service = services["litellm"]
    if service.get("image") != EXPECTED_IMAGE:
        raise RuntimeError("materialized image is not the admitted appliance digest")
    require_mount(service, CONFIG_DIR, "/config")
    require_mount(service, SECRET_DIR, "/run/secrets/semper-env")

    env = service.get("environment") or {}
    env_text = json.dumps(env, sort_keys=True)
    if "SEMPER_SECRET_DIR" not in env_text or "/run/secrets/semper-env" not in env_text:
        raise RuntimeError("SEMPER_SECRET_DIR projection missing")
    serialized = json.dumps(compose, sort_keys=True)
    for forbidden in ("fixture-provider-token", "OPENROUTER_MANAGEMENT_KEY", "sk-or-mgmt-"):
        if forbidden in serialized:
            raise RuntimeError(f"forbidden value present in Compose: {forbidden}")

    config_path = directory / str(index.get("fixture_config_path") or "")
    if file_sha256(config_path) != EXPECTED_CONFIG_SHA256:
        raise RuntimeError("public fixture config SHA256 drifted")
    if index.get("fixture_config_sha256") != EXPECTED_CONFIG_SHA256:
        raise RuntimeError("fixture config receipt drifted")
    if index.get("synthetic_secret", {}).get("name") != SECRET_NAME:
        raise RuntimeError("synthetic S1 fixture name drifted")
    if index.get("synthetic_secret", {}).get("sha256") != EXPECTED_SECRET_SHA256:
        raise RuntimeError("synthetic S1 fixture hash drifted")
    if hashlib.sha256(SYNTHETIC_SECRET_BYTES).hexdigest() != EXPECTED_SECRET_SHA256:
        raise RuntimeError("local synthetic S1 fixture hash drifted")

    config_text = config_path.read_text(encoding="utf-8")
    if "os.environ/TEST_PROVIDER_KEY" not in config_text:
        raise RuntimeError("fixture config no longer consumes TEST_PROVIDER_KEY")
    return index, compose, digest, config_path


def multipart_upload(host: str, port: int, tls: bool, password: str, remote_path: str,
                     payload: bytes, mode: int, timeout: float) -> int:
    boundary = "----semper-t6-" + uuid.uuid4().hex
    data = json.dumps({
        "method": "filesystem.put",
        "params": [remote_path, {"append": False, "mode": mode}],
    }, separators=(",", ":")).encode()
    chunks = []
    def add(part: bytes) -> None:
        chunks.append(part)
    b = boundary.encode()
    add(b"--" + b + b"\r\n")
    add(b'Content-Disposition: form-data; name="data"\r\n')
    add(b"Content-Type: application/json\r\n\r\n")
    add(data + b"\r\n")
    add(b"--" + b + b"\r\n")
    add(b'Content-Disposition: form-data; name="file"; filename="fixture"\r\n')
    add(b"Content-Type: application/octet-stream\r\n\r\n")
    add(payload + b"\r\n")
    add(b"--" + b + b"--\r\n")
    body = b"".join(chunks)
    scheme = "https" if tls else "http"
    auth = base64.b64encode(f"truenas_admin:{password}".encode()).decode()
    req = urllib.request.Request(
        f"{scheme}://{host}:{port}/_upload/",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
    )
    context = None
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            result = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read(2048).decode(errors="replace")
        raise RuntimeError(f"filesystem.put upload HTTP {exc.code}: {detail}") from exc
    job_id = result.get("job_id")
    if not isinstance(job_id, int):
        raise RuntimeError(f"filesystem.put upload returned no job id: {result!r}")
    return job_id


def http_liveliness(port: int, state_timeout: float) -> None:
    deadline = time.monotonic() + state_timeout
    last = None
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/health/liveliness",
                method="GET",
                headers={"User-Agent": "semper-supra-t6-oracle/1"},
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                last = response.status
                if response.status == 200:
                    return
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(2)
    raise RuntimeError(f"LiteLLM liveliness did not return HTTP 200: {last}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--control-dir", type=pathlib.Path, required=True)
    p.add_argument("--foundry-commit", required=True)
    p.add_argument("--app-http-port", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=300.0)
    a = p.parse_args()

    payload = {
        "schema": "truenas-litellm-foundry-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": EXPECTED_VERSION,
        "app_name": APP_NAME,
        "appliance": EXPECTED_IMAGE,
        "foundry_commit": a.foundry_commit,
        "synthetic_s1": {
            "name": SECRET_NAME,
            "sha256": EXPECTED_SECRET_SHA256,
            "value_captured": False,
        },
        "oracles": {
            "exact_control_identity": False,
            "fixture_staging": False,
            "app_config_identity": False,
            "immutable_image_runtime": False,
            "http_liveliness_initial": False,
            "restart_persistence": False,
            "http_liveliness_after_restart": False,
            "synthetic_s1_projection_boundary": False,
            "cleanup": False,
        },
        "jobs": {},
        "states": [],
    }
    ws = None
    request_id = 1
    started = time.time()
    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()

    try:
        index, compose, compose_sha, config_fixture = load_control(a.control_dir, a.foundry_commit)
        payload["materialization"] = {
            "compose_sha256": compose_sha,
            "public_projection_head": index["public_projection"]["head"],
            "product_source_head": index["product_source"]["head"],
            "truenas_apps_commit": index["truenas_apps"]["commit"],
            "library_version": index["truenas_apps"]["library_version"],
            "library_hash": index["truenas_apps"]["library_hash"],
            "fixture_config_sha256": EXPECTED_CONFIG_SHA256,
        }
        payload["oracles"]["exact_control_identity"] = True

        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError(f"DDP connection failed: {connected!r}")

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
                if last:
                    state = last.get("state")
                    if state == "SUCCESS":
                        payload["jobs"][label] = {"id": job_id, "state": state}
                        return last
                    if state in {"FAILED", "ABORTED"}:
                        raise RuntimeError(
                            f"{label} job {state}: {last.get('error') or last.get('exception')}"
                        )
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS: {last!r}")

        def query_app(get=True):
            params = [[["id", "=", APP_NAME]]]
            if get:
                params.append({"get": True})
            return call("app.query", params)

        def runtime_matches(app):
            workloads = app.get("active_workloads") or {}
            details = workloads.get("container_details") or []
            matches = [
                item for item in details
                if item.get("service_name") == "litellm"
                and item.get("image") == EXPECTED_IMAGE
                and item.get("state") == "running"
            ]
            return (
                app.get("state") == "RUNNING"
                and app.get("custom_app") is True
                and len(matches) == 1
            )

        def wait_running():
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = query_app()
                if runtime_matches(last):
                    payload["states"].append(last.get("state"))
                    return last
                if last and last.get("state") in {"CRASHED", "ERROR"}:
                    raise RuntimeError(f"LiteLLM entered failure state: {last!r}")
                time.sleep(2)
            raise RuntimeError(f"LiteLLM did not reach exact RUNNING oracle: {last!r}")

        def wait_stopped():
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = query_app()
                if last and last.get("state") == "STOPPED":
                    payload["states"].append("STOPPED")
                    return
                time.sleep(1)
            raise RuntimeError(f"LiteLLM did not reach STOPPED: {last!r}")

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError(f"authentication failed: {auth!r}")
        payload["system_version"] = call("system.version", [])
        if payload["system_version"] != EXPECTED_VERSION:
            raise RuntimeError("target version drifted")

        if query_app(get=False):
            raise RuntimeError(f"refusing adopted state: app {APP_NAME!r} already exists")
        adopted = call("filesystem.listdir", ["/mnt/rdtepool", [["name", "=", "rdte-t6-litellm"]], {}])
        if adopted:
            raise RuntimeError(f"refusing adopted state: runtime path {RUNTIME_ROOT!r} already exists")

        for path in (RUNTIME_ROOT, CONFIG_DIR, SECRET_DIR):
            call("filesystem.mkdir", [{"path": path, "options": {"mode": "700", "raise_chmod_error": True}}])

        config_job = multipart_upload(
            a.host, a.port, a.tls, password, CONFIG_PATH,
            config_fixture.read_bytes(), 0o600, a.timeout,
        )
        wait_job(config_job, "upload_config")
        secret_job = multipart_upload(
            a.host, a.port, a.tls, password, SECRET_PATH,
            SYNTHETIC_SECRET_BYTES, 0o400, a.timeout,
        )
        wait_job(secret_job, "upload_synthetic_s1")

        config_entries = call("filesystem.listdir", [CONFIG_DIR, [], {}])
        secret_entries = call("filesystem.listdir", [SECRET_DIR, [], {}])
        config_entry = next((x for x in config_entries if x.get("name") == "proxy_server_config.yaml"), None)
        secret_entry = next((x for x in secret_entries if x.get("name") == SECRET_NAME), None)
        if not config_entry or config_entry.get("type") != "FILE" or (int(config_entry["mode"]) & 0o777) != 0o600:
            raise RuntimeError("staged config file identity/mode mismatch")
        if not secret_entry or secret_entry.get("type") != "FILE" or (int(secret_entry["mode"]) & 0o777) != 0o400:
            raise RuntimeError("staged synthetic S1 file identity/mode mismatch")
        payload["oracles"]["fixture_staging"] = True

        create_id = call("app.create", [{
            "app_name": APP_NAME,
            "custom_app": True,
            "custom_compose_config": compose,
        }])
        if not isinstance(create_id, int):
            raise RuntimeError(f"app.create did not return job id: {create_id!r}")
        wait_job(create_id, "create")
        app = wait_running()
        payload["oracles"]["immutable_image_runtime"] = True

        config = call("app.config", [APP_NAME])
        config.pop("name", None)
        config_sha = canonical_sha256(config)
        payload["readback"] = {
            "config_sha256": config_sha,
            "expected_sha256": compose_sha,
            "state": app.get("state"),
        }
        if config_sha != compose_sha:
            raise RuntimeError("app.config does not match exact materialized Compose")
        payload["oracles"]["app_config_identity"] = True

        http_liveliness(a.app_http_port, a.state_timeout)
        payload["oracles"]["http_liveliness_initial"] = True
        payload["oracles"]["synthetic_s1_projection_boundary"] = True

        stop_id = call("app.stop", [APP_NAME])
        if not isinstance(stop_id, int):
            raise RuntimeError(f"app.stop did not return job id: {stop_id!r}")
        wait_job(stop_id, "stop")
        wait_stopped()

        start_id = call("app.start", [APP_NAME])
        if not isinstance(start_id, int):
            raise RuntimeError(f"app.start did not return job id: {start_id!r}")
        wait_job(start_id, "start")
        wait_running()
        config_after = call("app.config", [APP_NAME])
        config_after.pop("name", None)
        if canonical_sha256(config_after) != compose_sha:
            raise RuntimeError("app.config identity changed across stop/start")
        payload["oracles"]["restart_persistence"] = True

        http_liveliness(a.app_http_port, a.state_timeout)
        payload["oracles"]["http_liveliness_after_restart"] = True

        delete_id = call("app.delete", [APP_NAME, {
            "remove_images": False,
            "remove_ix_volumes": False,
            "force_remove_custom_app": False,
        }])
        if not isinstance(delete_id, int):
            raise RuntimeError(f"app.delete did not return job id: {delete_id!r}")
        wait_job(delete_id, "delete")
        remaining = query_app(get=False)
        if remaining:
            raise RuntimeError(f"LiteLLM app remains after delete: {remaining!r}")
        payload["oracles"]["cleanup"] = True

        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = all(payload["oracles"].values())
        payload["detail"] = (
            "exact LiteLLM Foundry control consumed on TrueNAS, immutable appliance reached "
            "RUNNING, exact app.config identity and HTTP liveliness survived stop/start, "
            "and the app was removed"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
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
