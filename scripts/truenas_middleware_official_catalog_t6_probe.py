#!/usr/bin/env python3
"""Bounded native official-catalog lifecycle oracle for disposable TrueNAS targets."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import time
from typing import Any

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for

EXPECTED_SCHEMA = "semper-supra.official-catalog-truenas-t6-control/1"
EXPECTED_FOUNDRY_REF = "be7c2e7fd81785ee3fce2a26f75d226004bf52e5"
EXPECTED_CATALOG_COMMIT = "8d93ac087336ab642492209cb707aa1f9556d324"
EXPECTED_CONTROL_ID = "ntfy"
EXPECTED_CATALOG_VERSION = "1.1.21"
EXPECTED_APP_VERSION = "v2.28.0"
EXPECTED_LIB_VERSION = "2.3.4"
EXPECTED_LIB_VERSION_HASH = "2e3a8847308fb2eb0da046018f287c73822c094b5950a10377c3235794ff1242"
BOOTSTRAP_METHODS = {"core.get_methods"}

REQUIRED_DISCOVERED_METHODS = {
    "system.version",
    "app.query",
    "app.config",
    "app.create",
    "app.update",
    "app.redeploy",
    "app.stop",
    "app.start",
    "app.delete",
    "app.upgrade",
}


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def load_control(root: pathlib.Path, foundry_commit: str) -> dict[str, Any]:
    path = root / "control.json"
    control = json.loads(path.read_text(encoding="utf-8"))
    if control.get("schema") != EXPECTED_SCHEMA:
        raise RuntimeError("official-catalog control schema drifted")
    if foundry_commit != EXPECTED_FOUNDRY_REF or control.get("foundry_ref") != EXPECTED_FOUNDRY_REF:
        raise RuntimeError("Foundry source identity drifted")
    source = control.get("catalog_source") or {}
    if source.get("commit") != EXPECTED_CATALOG_COMMIT:
        raise RuntimeError("catalog source commit drifted")
    item = control.get("control") or {}
    expected = {
        "id": EXPECTED_CONTROL_ID,
        "catalog_version": EXPECTED_CATALOG_VERSION,
        "app_version": EXPECTED_APP_VERSION,
        "lib_version": EXPECTED_LIB_VERSION,
        "lib_version_hash": EXPECTED_LIB_VERSION_HASH,
    }
    for key, value in expected.items():
        if item.get(key) != value:
            raise RuntimeError(f"control {key} drifted")
    if control.get("secrets_captured") is not False:
        raise RuntimeError("control unexpectedly captures secrets")
    if control.get("universal_qualified") is not False:
        raise RuntimeError("unqualified control falsely claims universal qualification")
    claimed = control.get("control_sha256")
    unsigned = dict(control)
    unsigned.pop("control_sha256", None)
    if claimed != canonical_sha256(unsigned):
        raise RuntimeError("control canonical identity mismatch")
    runtime = control.get("runtime") or {}
    create = runtime.get("create_payload") or {}
    if create.get("custom_app") is not False or create.get("catalog_app") != EXPECTED_CONTROL_ID:
        raise RuntimeError("control is not native-catalog create")
    if create.get("version") != EXPECTED_CATALOG_VERSION or create.get("train") != "community":
        raise RuntimeError("native-catalog create identity drifted")
    if (create.get("values") or {}).get("TZ") != "Etc/UTC":
        raise RuntimeError("initial config oracle drifted")
    update = runtime.get("config_update_payload") or {}
    if (update.get("values") or {}).get("TZ") != "Europe/Berlin":
        raise RuntimeError("update config oracle drifted")
    return control


def normalize_system_version(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("system.version did not return a non-empty string")
    return value.removeprefix("TrueNAS-")


def owned(app: dict[str, Any], control: dict[str, Any]) -> bool:
    item = control["control"]
    metadata = app.get("metadata") or {}
    return (
        app.get("custom_app") is False
        and app.get("version") == item["catalog_version"]
        and metadata.get("name") == item["id"]
        and metadata.get("app_version") == item["app_version"]
        and metadata.get("lib_version") == item["lib_version"]
        and metadata.get("lib_version_hash") == item["lib_version_hash"]
    )


def native_lineage(app: dict[str, Any], control: dict[str, Any]) -> bool:
    metadata = app.get("metadata") or {}
    return app.get("custom_app") is False and metadata.get("name") == control["control"]["id"]


def healthy_running(app: dict[str, Any], control: dict[str, Any]) -> bool:
    if not owned(app, control) or app.get("state") != "RUNNING":
        return False
    workloads = app.get("active_workloads") or {}
    details = workloads.get("container_details") or []
    containers = workloads.get("containers")
    if not isinstance(containers, int) or containers < 1 or not details:
        return False
    return all(item.get("state") == "running" for item in details)


def plan(
    app: dict[str, Any] | None,
    config: dict[str, Any] | None,
    control: dict[str, Any],
    *,
    desired_present: bool = True,
    desired_running: bool = True,
    desired_tz: str = "Etc/UTC",
) -> str:
    if app is None:
        return "CREATE" if desired_present else "NOOP"
    if not owned(app, control):
        return "BLOCK_FOREIGN"
    if not desired_present:
        return "DELETE"
    state = app.get("state")
    if desired_running and state == "STOPPED":
        return "START"
    if not desired_running and state == "RUNNING":
        return "STOP"
    if state not in {"RUNNING", "STOPPED"}:
        return "BLOCK_AMBIGUOUS"
    if (config or {}).get("TZ") != desired_tz:
        return "UPDATE"
    return "NOOP"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--control-dir", type=pathlib.Path, required=True)
    p.add_argument("--foundry-commit", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=240.0)
    a = p.parse_args()

    started = time.time()
    payload: dict[str, Any] = {
        "schema": "truenas-official-catalog-t6/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "foundry_commit": a.foundry_commit,
        "catalog_commit": EXPECTED_CATALOG_COMMIT,
        "control_id": EXPECTED_CONTROL_ID,
        "jobs": {},
        "states": [],
        "plans": [],
        "upgrade": None,
        "cleanup": {"attempted": False, "app_absent": False},
        "secret_values_captured": False,
    }
    ws = None
    request_id = 1
    created = False

    try:
        control = load_control(a.control_dir, a.foundry_commit)
        app_name = control["runtime"]["app_name"]
        payload["app_name"] = app_name
        password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()

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

        def wait_job(job_id: int, label: str):
            deadline = time.monotonic() + a.job_timeout
            last = None
            while time.monotonic() < deadline:
                last = call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
                if last:
                    state = last.get("state")
                    if state == "SUCCESS":
                        payload["jobs"][label] = {"id": job_id, "state": state}
                        return
                    if state in {"FAILED", "ABORTED"}:
                        raise RuntimeError(
                            f"{label} job {state}: {last.get('error') or last.get('exception')}"
                        )
                time.sleep(1)
            raise RuntimeError(f"{label} job did not reach SUCCESS")

        def query(get: bool = True):
            rows = call("app.query", [[["id", "=", app_name]]])
            if not rows:
                return None if get else []
            return rows[0] if get else rows

        def config():
            return call("app.config", [app_name])

        def wait_running(label: str):
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = query()
                if last and healthy_running(last, control):
                    payload["states"].append({"label": label, "state": "RUNNING"})
                    return last
                if last and last.get("state") in {"CRASHED", "ERROR"}:
                    raise RuntimeError(f"{label} entered failure state: {last!r}")
                time.sleep(1)
            raise RuntimeError(f"{label} did not become healthy RUNNING: {last!r}")

        def wait_native_running(label: str):
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = query()
                workloads = (last or {}).get("active_workloads") or {}
                details = workloads.get("container_details") or []
                if (
                    last
                    and native_lineage(last, control)
                    and last.get("state") == "RUNNING"
                    and isinstance(workloads.get("containers"), int)
                    and workloads.get("containers") >= 1
                    and details
                    and all(item.get("state") == "running" for item in details)
                ):
                    payload["states"].append({"label": label, "state": "RUNNING"})
                    return last
                time.sleep(1)
            raise RuntimeError(f"{label} did not become native-lineage RUNNING: {last!r}")

        def wait_state(expected: str, label: str):
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = query()
                if last and last.get("state") == expected and owned(last, control):
                    payload["states"].append({"label": label, "state": expected})
                    return last
                time.sleep(1)
            raise RuntimeError(f"{label} did not reach {expected}: {last!r}")

        def submit(method: str, params: list[Any], label: str):
            job_id = call(method, params)
            if not isinstance(job_id, int):
                raise RuntimeError(f"{method} did not return job id: {job_id!r}")
            wait_job(job_id, label)

        def observe(desired_tz: str, **desired):
            app = query()
            cfg = config() if app else None
            action = plan(app, cfg, control, desired_tz=desired_tz, **desired)
            payload["plans"].append({
                "action": action,
                "desired_present": desired.get("desired_present", True),
                "desired_running": desired.get("desired_running", True),
                "desired_tz": desired_tz,
                "observed_state": app.get("state") if app else "ABSENT",
                "observed_tz": cfg.get("TZ") if isinstance(cfg, dict) else None,
            })
            return action, app, cfg

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise RuntimeError("authentication did not return SUCCESS")

        system_version = call("system.version", [])
        payload["system_version"] = system_version
        target_version = normalize_system_version(system_version)
        payload["target_version"] = target_version
        if target_version not in control.get("target_versions", []):
            raise RuntimeError(
                f"target version {system_version!r} ({target_version!r}) is outside control matrix"
            )

        methods = call("core.get_methods", [])
        payload["bootstrap_probes"] = {"core.get_methods": True}
        method_names = set(methods) if isinstance(methods, dict) else set()
        missing = sorted(REQUIRED_DISCOVERED_METHODS - method_names)
        payload["required_methods_present"] = not missing
        payload["missing_methods"] = missing
        if missing:
            raise RuntimeError(f"required native catalog methods missing: {missing}")

        if query() is not None:
            raise RuntimeError("refusing adopted official-catalog control state")

        action, _, _ = observe("Etc/UTC")
        if action != "CREATE":
            raise RuntimeError(f"initial plan was not CREATE: {action}")
        submit("app.create", [control["runtime"]["create_payload"]], "create_1")
        created = True
        first = wait_running("create_1")
        first_cfg = config()
        if first_cfg.get("TZ") != "Etc/UTC":
            raise RuntimeError("initial catalog config did not read back TZ=Etc/UTC")
        payload["catalog_identity"] = {
            "catalog_version": first.get("version"),
            "app_version": (first.get("metadata") or {}).get("app_version"),
            "lib_version": (first.get("metadata") or {}).get("lib_version"),
            "lib_version_hash": (first.get("metadata") or {}).get("lib_version_hash"),
        }
        action, _, _ = observe("Etc/UTC")
        if action != "NOOP":
            raise RuntimeError(f"post-create replan was not NOOP: {action}")

        action, _, _ = observe("Etc/UTC", desired_running=False)
        if action != "STOP":
            raise RuntimeError(f"stop plan was not STOP: {action}")
        submit("app.stop", [app_name], "stop")
        wait_state("STOPPED", "stop")

        action, _, _ = observe("Etc/UTC", desired_running=True)
        if action != "START":
            raise RuntimeError(f"start plan was not START: {action}")
        submit("app.start", [app_name], "start")
        wait_running("start")

        action, _, _ = observe("Europe/Berlin")
        if action != "UPDATE":
            raise RuntimeError(f"config plan was not UPDATE: {action}")
        submit("app.update", [app_name, control["runtime"]["config_update_payload"]], "update")
        wait_running("update")
        updated_cfg = config()
        if updated_cfg.get("TZ") != "Europe/Berlin":
            raise RuntimeError("app.config did not read back TZ=Europe/Berlin")
        action, _, _ = observe("Europe/Berlin")
        if action != "NOOP":
            raise RuntimeError(f"post-update replan was not NOOP: {action}")

        submit("app.redeploy", [app_name], "redeploy")
        wait_running("redeploy")

        action, _, _ = observe("Europe/Berlin", desired_present=False)
        if action != "DELETE":
            raise RuntimeError(f"retain-data delete plan was not DELETE: {action}")
        submit("app.delete", [app_name, control["runtime"]["delete_options"]], "delete_retain")
        created = False
        if query() is not None:
            raise RuntimeError("app still exists after retain-data delete")
        payload["retain_data_delete"] = {"app_absent": True, **control["runtime"]["delete_options"]}

        action, _, _ = observe("Etc/UTC")
        if action != "CREATE":
            raise RuntimeError(f"reinstall plan was not CREATE: {action}")
        submit("app.create", [control["runtime"]["create_payload"]], "create_2")
        created = True
        wait_running("create_2")
        re_cfg = config()
        if re_cfg.get("TZ") != "Etc/UTC":
            raise RuntimeError("reinstalled config did not read back initial TZ")
        action, _, _ = observe("Etc/UTC")
        if action != "NOOP":
            raise RuntimeError(f"post-reinstall replan was not NOOP: {action}")

        before_upgrade = query()
        if before_upgrade.get("upgrade_available") is True:
            before_version = before_upgrade.get("version")
            submit("app.upgrade", [app_name, {}], "upgrade")
            after_upgrade = wait_native_running("upgrade")
            payload["upgrade"] = {
                "status": "EXECUTED",
                "from_version": before_version,
                "to_version": after_upgrade.get("version"),
                "discovered_identity": {
                    "catalog_version": after_upgrade.get("version"),
                    "app_version": (after_upgrade.get("metadata") or {}).get("app_version"),
                    "lib_version": (after_upgrade.get("metadata") or {}).get("lib_version"),
                    "lib_version_hash": (after_upgrade.get("metadata") or {}).get("lib_version_hash"),
                },
            }
            if after_upgrade.get("version") == before_version:
                raise RuntimeError("native app.upgrade did not change catalog version")
        else:
            payload["upgrade"] = {
                "status": "NOT_APPLICABLE",
                "observed_upgrade_available": before_upgrade.get("upgrade_available"),
                "receipt_required": True,
            }

        destructive = {
            "remove_images": False,
            "remove_ix_volumes": True,
            "force_remove_custom_app": False,
        }
        submit("app.delete", [app_name, destructive], "cleanup_delete")
        created = False
        payload["cleanup"]["attempted"] = True
        payload["cleanup"]["app_absent"] = query() is None
        payload["cleanup"]["remove_ix_volumes"] = True
        if not payload["cleanup"]["app_absent"]:
            raise RuntimeError("official-catalog app remained after final cleanup")

        payload["classification"] = "SUPPORTED"
        payload["oracleSatisfied"] = True
        payload["detail"] = (
            "exact native catalog control converged CREATE/NOOP, stop/start, config UPDATE/read-back/NOOP, "
            "conditional native upgrade receipt, redeploy, retain-data delete, reinstall/NOOP, and final cleanup"
        )
    except Exception as exc:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
        if ws is not None and created:
            payload["cleanup"]["attempted"] = True
            try:
                rows = call("app.query", [[["id", "=", payload.get("app_name")]]])
                if rows:
                    job_id = call("app.delete", [payload["app_name"], {
                        "remove_images": False,
                        "remove_ix_volumes": True,
                        "force_remove_custom_app": False,
                    }])
                    if isinstance(job_id, int):
                        wait_job(job_id, "failure_cleanup")
                payload["cleanup"]["app_absent"] = not call(
                    "app.query", [[["id", "=", payload.get("app_name")]]]
                )
            except Exception as cleanup_exc:
                payload["cleanup"]["error"] = f"{type(cleanup_exc).__name__}: {cleanup_exc}"
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
