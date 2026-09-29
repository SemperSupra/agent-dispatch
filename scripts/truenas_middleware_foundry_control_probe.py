#!/usr/bin/env python3
"""TrueNAS T6 oracle: consume one exact public Foundry materialization control."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_UPSTREAM_REF = "532236882212e8c5e51d5b49cfe2c6ce3dd5675e"
EXPECTED_LIBRARY_VERSION = "2.3.4"
EXPECTED_LIBRARY_HASH = "2e3a8847308fb2eb0da046018f287c73822c094b5950a10377c3235794ff1242"
EXPECTED_ROLE = "t6-live-stateless-control"
EXPECTED_APP = "element-web"
APP_NAME = "rdte-t6-element-web"


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_control(directory: pathlib.Path, role: str):
    index_path = directory / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index.get("schema") != "truenas-foundry-materialized-controls/v1":
        raise RuntimeError("unexpected Foundry control index schema")
    upstream = index.get("upstream") or {}
    if upstream.get("ref") != EXPECTED_UPSTREAM_REF:
        raise RuntimeError("Foundry upstream ref drifted")
    if upstream.get("library_version") != EXPECTED_LIBRARY_VERSION:
        raise RuntimeError("Foundry library version drifted")
    if upstream.get("library_hash") != EXPECTED_LIBRARY_HASH:
        raise RuntimeError("Foundry library hash drifted")

    matches = [
        c for c in index.get("controls", [])
        if c.get("runtime_safe") is True
        and c.get("qualification_role") == role
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one runtime-safe {role!r} control, got {len(matches)}")
    control = matches[0]
    if control.get("app") != EXPECTED_APP:
        raise RuntimeError(f"unexpected T6 control app: {control.get('app')!r}")
    compose_path = directory / str(control.get("compose_path") or "")
    compose = json.loads(compose_path.read_text(encoding="utf-8"))
    if not isinstance(compose.get("services"), dict) or not compose["services"]:
        raise RuntimeError("Foundry Compose has no services")
    digest = canonical_sha256(compose)
    if digest != control.get("compose_sha256"):
        raise RuntimeError("Foundry Compose SHA256 does not match index")

    # The first live control is intentionally stateless. Reject any bind/host path
    # even if a future source change accidentally reintroduces one.
    for service in compose["services"].values():
        for volume in service.get("volumes") or []:
            if isinstance(volume, dict):
                if volume.get("type") == "bind":
                    raise RuntimeError("T6 live control unexpectedly contains bind storage")
                source = str(volume.get("source") or "")
                if source.startswith("/"):
                    raise RuntimeError("T6 live control unexpectedly contains absolute host storage")
            elif isinstance(volume, str):
                source = volume.split(":", 1)[0]
                if source.startswith("/"):
                    raise RuntimeError("T6 live control unexpectedly contains absolute host storage")
    return index, control, compose, digest


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--control-dir", type=pathlib.Path, required=True)
    p.add_argument("--foundry-commit", required=True)
    p.add_argument("--control-role", default=EXPECTED_ROLE)
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=240.0)
    a = p.parse_args()

    payload = {
        "schema": "truenas-foundry-control-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "expected_version": EXPECTED_VERSION,
        "app_name": APP_NAME,
        "foundry_commit": a.foundry_commit,
        "control_role": a.control_role,
        "image_mutability_limitation": True,
    }
    ws = None
    started = time.time()
    try:
        index, control, compose, compose_sha = load_control(a.control_dir, a.control_role)
        payload["materialization"] = {
            "schema": index["schema"],
            "upstream": index["upstream"],
            "control": {
                "app": control["app"],
                "test_file": control["test_file"],
                "primary_service": control["primary_service"],
                "compose_sha256": compose_sha,
                "runtime_safe": control["runtime_safe"],
                "qualification_role": control["qualification_role"],
            },
            "services": sorted(compose["services"]),
            "images": sorted({
                str(s.get("image"))
                for s in compose["services"].values()
                if s.get("image")
            }),
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
                    return last
                if last and last.get("state") in {"FAILED", "ABORTED"}:
                    raise RuntimeError(f"{label} job {last.get('state')}: {last.get('error') or last.get('exception')}")
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS: {last!r}")

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

        existing = call("app.query", [[["id", "=", APP_NAME]]])
        if existing:
            raise RuntimeError(f"refusing adopted state: {APP_NAME!r} already exists")

        job_id = call("app.create", [{
            "app_name": APP_NAME,
            "custom_app": True,
            "custom_compose_config": compose,
        }])
        if not isinstance(job_id, int):
            raise RuntimeError(f"app.create did not return a job id: {job_id!r}")
        job = wait_job(job_id, "app.create")
        payload["create_job"] = {"id": job_id, "state": job.get("state")}

        deadline = time.monotonic() + a.state_timeout
        app = None
        while time.monotonic() < deadline:
            app = call("app.query", [[["id", "=", APP_NAME]], {"get": True}])
            if app:
                workloads = app.get("active_workloads") or {}
                details = workloads.get("container_details") or []
                if (
                    app.get("state") == "RUNNING"
                    and app.get("custom_app") is True
                    and int(workloads.get("containers") or 0) >= 1
                    and any(d.get("state") == "running" for d in details)
                ):
                    break
                if app.get("state") in {"CRASHED", "ERROR"}:
                    raise RuntimeError(f"Foundry control entered failure state: {app!r}")
            time.sleep(1)
        else:
            raise RuntimeError(f"Foundry control did not reach RUNNING: {app!r}")

        config = call("app.config", [APP_NAME])
        config_sha = canonical_sha256(config)
        payload["readback"] = {
            "state": app.get("state"),
            "custom_app": app.get("custom_app"),
            "containers": (app.get("active_workloads") or {}).get("containers"),
            "config_sha256": config_sha,
            "config_matches_foundry": config_sha == compose_sha,
        }
        if config_sha != compose_sha:
            raise RuntimeError("app.config read-back does not match the exact Foundry Compose identity")

        delete_id = call("app.delete", [APP_NAME, {
            "remove_images": False,
            "remove_ix_volumes": False,
            "force_remove_custom_app": False,
        }])
        if not isinstance(delete_id, int):
            raise RuntimeError(f"app.delete did not return a job id: {delete_id!r}")
        delete_job = wait_job(delete_id, "app.delete")
        payload["delete_job"] = {"id": delete_id, "state": delete_job.get("state")}
        remaining = call("app.query", [[["id", "=", APP_NAME]]])
        payload["post_delete_query_count"] = len(remaining) if isinstance(remaining, list) else None
        if remaining:
            raise RuntimeError("Foundry control still exists after cleanup")

        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "exact public Foundry materialization control was consumed as a TrueNAS Custom App, "
            "reached RUNNING, matched app.config by canonical SHA256, and was removed"
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
