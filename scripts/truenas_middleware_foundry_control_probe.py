#!/usr/bin/env python3
"""TrueNAS T6 oracle for an exact Foundry-exported runtime-safe deployment artifact."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import time
from typing import Any

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
CONTROL_ROLE = "t6-live-stateless-control"


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_artifact(root: pathlib.Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    index = load_json(root / "index.json")
    if index.get("schema") != "truenas-foundry-materialized-controls/v1":
        raise RuntimeError("unsupported Foundry controls index schema")
    controls = [
        c for c in index.get("controls", [])
        if c.get("runtime_safe") is True and c.get("qualification_role") == CONTROL_ROLE
    ]
    if len(controls) != 1:
        raise RuntimeError(f"expected exactly one {CONTROL_ROLE} control, got {len(controls)}")
    control = controls[0]
    rel = control.get("deployment_artifact_path")
    if not isinstance(rel, str) or not rel:
        raise RuntimeError("runtime-safe control has no deployment_artifact_path")
    artifact_path = root / rel
    artifact_bytes = artifact_path.read_bytes()
    if hashlib.sha256(artifact_bytes).hexdigest() != control.get("deployment_artifact_file_sha256"):
        raise RuntimeError("deployment artifact file SHA-256 mismatch")
    artifact = json.loads(artifact_bytes)
    if artifact.get("schema") != "truenas-foundry-deployment-artifact/v1":
        raise RuntimeError("unsupported deployment artifact schema")
    if artifact.get("artifact_sha256") != control.get("deployment_artifact_sha256"):
        raise RuntimeError("deployment artifact envelope identity mismatch")
    body = dict(artifact)
    body.pop("artifact_sha256", None)
    if canonical_sha256(body) != artifact.get("artifact_sha256"):
        raise RuntimeError("deployment artifact canonical identity mismatch")
    compose = artifact.get("create_payload", {}).get("custom_compose_config")
    if not isinstance(compose, dict) or not compose.get("services"):
        raise RuntimeError("deployment artifact has no Compose services")
    if canonical_sha256(compose) != artifact.get("compose_sha256"):
        raise RuntimeError("deployment artifact Compose hash mismatch")
    if artifact.get("materialization_identity") != "sha256:" + artifact["compose_sha256"]:
        raise RuntimeError("deployment artifact materialization identity mismatch")
    for name, service in compose["services"].items():
        image = service.get("image")
        if image and "@sha256:" not in str(image):
            raise RuntimeError(f"service {name} image is not digest pinned")
        if service.get("privileged") is True:
            raise RuntimeError(f"service {name} is privileged")
        for volume in service.get("volumes") or []:
            if isinstance(volume, dict):
                src = str(volume.get("source") or "")
                typ = str(volume.get("type") or "")
                if typ == "bind" or src.startswith("/") or "/var/run/docker.sock" in src:
                    raise RuntimeError(f"service {name} has disallowed host bind/socket")
            elif isinstance(volume, str):
                src = volume.split(":", 1)[0]
                if src.startswith("/") or "/var/run/docker.sock" in src:
                    raise RuntimeError(f"service {name} has disallowed host bind/socket")
    return index, control, artifact


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--artifact-dir", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=180.0)
    a = p.parse_args()

    payload: dict[str, Any] = {
        "schema": "truenas-foundry-runtime-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "control_role": CONTROL_ROLE,
    }
    ws = None
    started = time.time()
    try:
        index, control, artifact = validate_artifact(a.artifact_dir)
        payload["foundry"] = {
            "upstream": index.get("upstream"),
            "control_app": control.get("app"),
            "source_compose_sha256": control.get("source_compose_sha256"),
            "deployment_artifact_sha256": artifact.get("artifact_sha256"),
            "materialization_identity": artifact.get("materialization_identity"),
            "app_name": artifact.get("app_name"),
            "image_digests": control.get("image_digests"),
            "target_lowering": control.get("target_lowering"),
        }
        password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError(f"DDP connection failed: {connected!r}")
        request_id = 1

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
                    payload.setdefault("jobs", {})[label] = {
                        "id": job_id,
                        "state": "SUCCESS",
                    }
                    return
                if last and last.get("state") in {"FAILED", "ABORTED"}:
                    raise RuntimeError(f"{label} job failed: {last.get('error')}")
                time.sleep(1)
            raise RuntimeError(f"{label} job did not finish: {last!r}")

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError("authentication did not return SUCCESS")
        version = call("system.version", [])
        payload["system_version"] = version
        if version != EXPECTED_VERSION:
            raise RuntimeError(f"target version changed: {version!r}")

        app_name = artifact["app_name"]
        existing = call("app.query", [[["id", "=", app_name]]])
        if existing:
            raise RuntimeError("T6 app already exists before create")

        job_id = call("app.create", [artifact["create_payload"]])
        if not isinstance(job_id, int):
            raise RuntimeError(f"app.create did not return a job id: {job_id!r}")
        wait_job(job_id, "create")

        deadline = time.monotonic() + a.state_timeout
        app = None
        while time.monotonic() < deadline:
            app = call("app.query", [[["id", "=", app_name]], {"get": True}])
            workloads = (app or {}).get("active_workloads") or {}
            details = workloads.get("container_details") or []
            if (
                app
                and app.get("state") == "RUNNING"
                and app.get("custom_app") is True
                and int(workloads.get("containers") or 0) >= 1
                and any(d.get("state") == "running" for d in details)
            ):
                break
            time.sleep(1)
        else:
            raise RuntimeError(f"Foundry app did not reach RUNNING: {app!r}")

        config = call("app.config", [app_name])
        config_sha = canonical_sha256(config)
        payload["runtime"] = {
            "state": app.get("state"),
            "custom_app": app.get("custom_app"),
            "containers": (app.get("active_workloads") or {}).get("containers"),
            "config_sha256": config_sha,
        }
        if config_sha != artifact["compose_sha256"]:
            raise RuntimeError("app.config does not match Foundry deployment artifact")

        delete_id = call("app.delete", [app_name, {
            "remove_images": False,
            "remove_ix_volumes": True,
            "force_remove_custom_app": False,
        }])
        if not isinstance(delete_id, int):
            raise RuntimeError(f"app.delete did not return a job id: {delete_id!r}")
        wait_job(delete_id, "delete")
        remaining = call("app.query", [[["id", "=", app_name]]])
        if remaining:
            raise RuntimeError("Foundry app remains after cleanup")

        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "exact Foundry runtime-safe deployment artifact created, independently "
            "matched app.config/runtime state, and deleted"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        if ws is not None:
            ws.close()

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    a.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
