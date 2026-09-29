#!/usr/bin/env python3
"""Bounded TrueNAS 26.0.0-BETA.3 T5 custom-app lifecycle oracle."""
from __future__ import annotations

import argparse
import json
import pathlib
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
APP_NAME = "rdte-t4-probe"
APP_IMAGE = "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=180.0)
    a = p.parse_args()

    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
    payload = {
        "schema": "truenas-app-lifecycle-t5/v2",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": EXPECTED_VERSION,
        "app_name": APP_NAME,
        "app_image": APP_IMAGE,
        "transport": "wss" if a.tls else "ws",
        "jobs": {},
        "states": [],
    }
    ws = None
    request_id = 1
    started = time.time()

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
                        payload["jobs"][label] = {
                            "id": job_id,
                            "state": state,
                            "progress": last.get("progress"),
                            "result": last.get("result"),
                        }
                        return last
                    if state in {"FAILED", "ABORTED"}:
                        raise RuntimeError(
                            f"{label} job {state}: {last.get('error') or last.get('exception')}"
                        )
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS: {last!r}")

        def app_query(get=True):
            params = [[["id", "=", APP_NAME]]]
            if get:
                params.append({"get": True})
            return call("app.query", params)

        def running(app):
            workloads = app.get("active_workloads") or {}
            details = workloads.get("container_details") or []
            return (
                app.get("state") == "RUNNING"
                and app.get("custom_app") is True
                and workloads.get("containers") == 1
                and len(details) == 1
                and details[0].get("service_name") == "web"
                and details[0].get("image") == APP_IMAGE
                and details[0].get("state") == "running"
            )

        def wait_state(expected, require_running=False):
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = app_query()
                if require_running:
                    if running(last):
                        payload["states"].append(last.get("state"))
                        return last
                elif last.get("state") == expected:
                    payload["states"].append(last.get("state"))
                    return last
                if last.get("state") in {"CRASHED", "ERROR"}:
                    raise RuntimeError(
                        f"app entered failure state while waiting for {expected}: {last!r}"
                    )
                time.sleep(1)
            raise RuntimeError(f"app did not reach {expected}: {last!r}")

        auth = call(
            "auth.login_ex",
            [{
                "mechanism": "PASSWORD_PLAIN",
                "username": "truenas_admin",
                "password": password,
            }],
        )
        payload["auth_response_type"] = (
            auth.get("response_type") if isinstance(auth, dict) else None
        )
        if payload["auth_response_type"] != "SUCCESS":
            raise RuntimeError(f"authentication did not return SUCCESS: {auth!r}")

        version = call("system.version", [])
        payload["system_version"] = version
        if version != EXPECTED_VERSION:
            raise RuntimeError(
                f"target version changed: expected {EXPECTED_VERSION!r}, got {version!r}"
            )

        initial = app_query()
        if not running(initial):
            raise RuntimeError(f"T5 requires the exact T4 app already RUNNING: {initial!r}")
        payload["states"].append(initial["state"])

        job_id = call("app.stop", [APP_NAME])
        if not isinstance(job_id, int):
            raise RuntimeError(f"app.stop did not return a job id: {job_id!r}")
        wait_job(job_id, "stop_1")
        wait_state("STOPPED")

        job_id = call("app.start", [APP_NAME])
        if not isinstance(job_id, int):
            raise RuntimeError(f"app.start did not return a job id: {job_id!r}")
        wait_job(job_id, "start")
        wait_state("RUNNING", require_running=True)

        updated_compose = {
            "services": {
                "web": {
                    "image": APP_IMAGE,
                    "restart": "unless-stopped",
                    "environment": {"RDTE_GENERATION": "2"},
                }
            }
        }
        job_id = call(
            "app.update",
            [APP_NAME, {"custom_compose_config": updated_compose}],
        )
        if not isinstance(job_id, int):
            raise RuntimeError(f"app.update did not return a job id: {job_id!r}")
        wait_job(job_id, "update")

        config = call("app.config", [APP_NAME])
        payload["config_after_update"] = config
        generation = (
            config.get("services", {})
            .get("web", {})
            .get("environment", {})
            .get("RDTE_GENERATION")
        )
        if str(generation) != "2":
            raise RuntimeError(
                f"app.config did not read back RDTE_GENERATION=2: {config!r}"
            )
        config_image = config.get("services", {}).get("web", {}).get("image")
        if config_image != APP_IMAGE:
            raise RuntimeError(
                f"app.config image drifted from immutable T4 digest: {config_image!r}"
            )
        wait_state("RUNNING", require_running=True)

        job_id = call("app.redeploy", [APP_NAME])
        if not isinstance(job_id, int):
            raise RuntimeError(f"app.redeploy did not return a job id: {job_id!r}")
        wait_job(job_id, "redeploy")
        wait_state("RUNNING", require_running=True)

        job_id = call("app.stop", [APP_NAME])
        if not isinstance(job_id, int):
            raise RuntimeError(f"second app.stop did not return a job id: {job_id!r}")
        wait_job(job_id, "stop_2")
        wait_state("STOPPED")

        job_id = call(
            "app.delete",
            [APP_NAME, {
                "remove_images": True,
                "remove_ix_volumes": True,
                "force_remove_custom_app": False,
            }],
        )
        if not isinstance(job_id, int):
            raise RuntimeError(f"app.delete did not return a job id: {job_id!r}")
        wait_job(job_id, "delete")

        remaining = app_query(get=False)
        payload["post_delete_query"] = remaining
        if remaining:
            raise RuntimeError(f"app still exists after delete: {remaining!r}")

        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "digest-pinned custom app completed stop/start, config mutation with "
            "public read-back, redeploy, stop, and delete"
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
