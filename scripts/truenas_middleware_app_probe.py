#!/usr/bin/env python3
"""Bounded TrueNAS BETA.3 Apps T4 oracle using source-defined middleware APIs."""
from __future__ import annotations

import argparse
import json
import pathlib
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


APP_NAME = "rdte-t4-probe"
APP_IMAGE = "nginx:1.27-alpine"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--pool-name", default="rdtepool")
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=180.0)
    a = p.parse_args()

    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
    payload = {
        "schema": "truenas-middleware-app-t4/v1",
        "source_contract": {
            "middleware_tag": "TS-26.0.0-BETA.3",
            "middleware_commit": "81e1265a86083888ba94a2bdfc02ff5c9c5ef6a3",
            "apps_gate": "docker.license_active",
        },
        "oracleSatisfied": False,
        "classification": "ORACLE_FAILURE",
        "pool_name": a.pool_name,
        "app_name": APP_NAME,
        "app_image": APP_IMAGE,
        "transport": "wss" if a.tls else "ws",
    }
    started = time.time()
    ws = None
    request_id = 1

    try:
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
                        return last
                    if state in {"FAILED", "ABORTED"}:
                        raise RuntimeError(
                            f"{label} job {state}: {last.get('error') or last.get('exception')}"
                        )
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS within timeout: {last!r}")

        auth = call(
            "auth.login_ex",
            [{
                "mechanism": "PASSWORD_PLAIN",
                "username": "truenas_admin",
                "password": password,
            }],
        )
        payload["auth_response_type"] = auth.get("response_type") if isinstance(auth, dict) else None
        if payload["auth_response_type"] != "SUCCESS":
            raise RuntimeError(f"authentication did not return SUCCESS: {auth!r}")

        payload["system_version"] = call("system.version", [])
        payload["docker_before"] = call("docker.config", [])
        existing = call("app.query", [[[ "id", "=", APP_NAME ]]])
        if existing:
            raise RuntimeError(f"refusing mutation: app {APP_NAME!r} already exists")

        docker_job_id = call("docker.update", [{"pool": a.pool_name}])
        if not isinstance(docker_job_id, int):
            raise RuntimeError(f"docker.update did not return a job id: {docker_job_id!r}")
        payload["docker_update_job_id"] = docker_job_id
        docker_job = wait_job(docker_job_id, "docker.update")
        payload["docker_update_job"] = {
            "id": docker_job.get("id"),
            "state": docker_job.get("state"),
            "progress": docker_job.get("progress"),
        }
        payload["docker_update_result"] = docker_job.get("result")

        deadline = time.monotonic() + a.state_timeout
        docker_status = None
        while time.monotonic() < deadline:
            docker_status = call("docker.status", [])
            if isinstance(docker_status, dict) and docker_status.get("status") == "RUNNING":
                break
            if isinstance(docker_status, dict) and docker_status.get("status") in {"FAILED", "MIGRATION_FAILED"}:
                raise RuntimeError(f"Docker entered failure state: {docker_status!r}")
            time.sleep(1)
        else:
            raise RuntimeError(f"Docker did not reach RUNNING: {docker_status!r}")
        payload["docker_status"] = docker_status

        docker_config = call("docker.config", [])
        payload["docker_config"] = docker_config
        if docker_config.get("pool") != a.pool_name:
            raise RuntimeError(
                f"Docker pool mismatch: expected {a.pool_name!r}, got {docker_config.get('pool')!r}"
            )

        compose = {
            "services": {
                "web": {
                    "image": APP_IMAGE,
                    "restart": "unless-stopped",
                }
            }
        }
        payload["create_contract"] = {
            "app_name": APP_NAME,
            "custom_app": True,
            "custom_compose_config": compose,
        }
        app_job_id = call("app.create", [{
            "app_name": APP_NAME,
            "custom_app": True,
            "custom_compose_config": compose,
        }])
        if not isinstance(app_job_id, int):
            raise RuntimeError(f"app.create did not return a job id: {app_job_id!r}")
        payload["app_create_job_id"] = app_job_id
        app_job = wait_job(app_job_id, "app.create")
        payload["app_create_job"] = {
            "id": app_job.get("id"),
            "state": app_job.get("state"),
            "progress": app_job.get("progress"),
        }
        payload["app_create_result"] = app_job.get("result")

        deadline = time.monotonic() + a.state_timeout
        app = None
        while time.monotonic() < deadline:
            app = call("app.query", [[[ "id", "=", APP_NAME ]], {"get": True}])
            if app:
                workloads = app.get("active_workloads") or {}
                details = workloads.get("container_details") or []
                matching = [
                    c for c in details
                    if c.get("service_name") == "web"
                    and c.get("image") == APP_IMAGE
                    and c.get("state") == "running"
                ]
                if (
                    app.get("state") == "RUNNING"
                    and app.get("custom_app") is True
                    and workloads.get("containers") == 1
                    and len(matching) == 1
                ):
                    break
                if app.get("state") == "CRASHED":
                    raise RuntimeError(f"custom app entered CRASHED state: {app!r}")
            time.sleep(1)
        else:
            raise RuntimeError(f"custom app did not reach the running oracle: {app!r}")

        payload["app"] = app
        payload["oracleSatisfied"] = True
        payload["classification"] = "SUPPORTED"
        payload["detail"] = (
            "Apps initialized on the real disposable ZFS pool and a source-shaped custom Compose app "
            "reached RUNNING with exactly one expected nginx container"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        if ws is not None:
            ws.close()

    payload["elapsed_seconds"] = round(time.time() - started, 3)
    pathlib.Path(a.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
