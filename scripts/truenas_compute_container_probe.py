#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import time
from typing import Any

try:
    from scripts.compute_materialization_contract import ContractError, choose_adapter, load, target, validate
    from scripts.truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for
except ModuleNotFoundError:
    from compute_materialization_contract import ContractError, choose_adapter, load, target, validate
    from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


class ProbeError(RuntimeError):
    pass


def normalize_system_version(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ProbeError(f"invalid system.version: {value!r}")
    return value.removeprefix("TrueNAS-")


def observed_state(row: dict[str, Any] | None) -> str:
    if not row:
        return "ABSENT"
    value = row.get("status")
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("state"), str):
        return value["state"]
    return "UNKNOWN"


def build_create_payload(
    adapter_id: str,
    name: str,
    nonce: str,
    *,
    legacy_image: str | None = None,
    image_name: str | None = None,
    image_version: str | None = None,
    pool: str | None = None,
) -> dict[str, Any]:
    if adapter_id == "truenas-virt-incus-container":
        if not legacy_image:
            raise ProbeError("legacy Incus adapter requires --legacy-image")
        payload: dict[str, Any] = {
            "name": name,
            "source_type": "IMAGE",
            "image": legacy_image,
            "remote": "LINUX_CONTAINERS",
            "instance_type": "CONTAINER",
            "autostart": False,
            "environment": {"RDTE_NONCE": nonce, "RDTE_GENERATION": "1"},
            "memory": 256 * 1024 * 1024,
        }
        if pool:
            payload["storage_pool"] = pool
        return payload
    if adapter_id == "truenas-container-lxc":
        if not image_name or not image_version:
            raise ProbeError("LXC adapter requires --image-name and --image-version")
        payload = {
            "name": name,
            "description": "Agent Dispatch disposable C0 compute-materialization fixture",
            "autostart": False,
            "time": "UTC",
            "initenv": {"RDTE_NONCE": nonce, "RDTE_GENERATION": "1"},
            "idmap": {"type": "DEFAULT"},
            "capabilities_policy": "DEFAULT",
            "image": {"name": image_name, "version": image_version},
        }
        if pool:
            payload["pool"] = pool
        return payload
    raise ProbeError(f"unsupported container adapter: {adapter_id}")


def resolve_image_identity(
    adapter: dict[str, Any],
    call,
    *,
    legacy_image: str | None = None,
    image_name: str | None = None,
    image_version: str | None = None,
) -> tuple[dict[str, str], dict[str, Any]]:
    adapter_id = adapter.get("id")
    discovery = adapter.get("image_discovery")
    if not isinstance(discovery, dict):
        raise ProbeError(f"{adapter_id}: image discovery contract missing")
    method = discovery.get("method")
    selection = discovery.get("selection")
    if not isinstance(method, str) or not isinstance(selection, dict):
        raise ProbeError(f"{adapter_id}: invalid image discovery contract")

    if adapter_id == "truenas-virt-incus-container":
        request = discovery.get("request")
        if not isinstance(request, dict):
            raise ProbeError("legacy image discovery request missing")
        choices = call(method, [request])
        if not isinstance(choices, dict):
            raise ProbeError(f"legacy image choices invalid: {choices!r}")
        alias = selection.get("alias")
        if not isinstance(alias, str) or not alias:
            raise ProbeError("legacy image alias contract missing")
        if legacy_image is not None and legacy_image != alias:
            raise ProbeError(f"explicit legacy image {legacy_image!r} does not match admitted alias {alias!r}")
        observed = choices.get(alias)
        if not isinstance(observed, dict):
            raise ProbeError(f"admitted legacy image alias unavailable: {alias!r}")
        if selection.get("instance_type") not in set(observed.get("instance_types") or []):
            raise ProbeError(f"legacy image lacks required instance type: {observed!r}")
        if selection.get("arch") not in set(observed.get("archs") or []):
            raise ProbeError(f"legacy image lacks required architecture: {observed!r}")
        return {"legacy_image": alias}, {
            "method": method,
            "source": discovery.get("source"),
            "selected": {"alias": alias},
            "observed": observed,
        }

    if adapter_id == "truenas-container-lxc":
        rows = call(method, [])
        if not isinstance(rows, list):
            raise ProbeError(f"container image registry response invalid: {rows!r}")
        name = selection.get("name")
        if not isinstance(name, str) or not name:
            raise ProbeError("LXC image name contract missing")
        if image_name is not None and image_name != name:
            raise ProbeError(f"explicit image name {image_name!r} does not match admitted name {name!r}")
        observed = next((x for x in rows if isinstance(x, dict) and x.get("name") == name), None)
        if not isinstance(observed, dict):
            raise ProbeError(f"admitted LXC image name unavailable: {name!r}")
        versions = [
            x.get("version") for x in (observed.get("versions") or [])
            if isinstance(x, dict) and isinstance(x.get("version"), str) and x.get("version")
        ]
        if not versions:
            raise ProbeError(f"admitted LXC image has no exact versions: {observed!r}")
        chosen = image_version or versions[-1]
        if chosen not in versions:
            raise ProbeError(f"requested LXC image version {chosen!r} not returned by registry")
        return {"image_name": name, "image_version": chosen}, {
            "method": method,
            "source": discovery.get("source"),
            "selected": {"name": name, "version": chosen},
            "available_versions": versions,
        }

    raise ProbeError(f"unsupported container adapter for image discovery: {adapter_id}")


def update_payload(adapter_id: str, nonce: str) -> dict[str, Any]:
    if adapter_id == "truenas-virt-incus-container":
        return {"environment": {"RDTE_NONCE": nonce, "RDTE_GENERATION": "2"}}
    if adapter_id == "truenas-container-lxc":
        return {
            "description": "Agent Dispatch disposable C0 compute-materialization fixture generation 2",
            "initenv": {"RDTE_NONCE": nonce, "RDTE_GENERATION": "2"},
        }
    raise ProbeError(f"unsupported container adapter: {adapter_id}")


def method_shapes(adapter_id: str, name: str, row_id: Any | None = None) -> dict[str, tuple[str, list[Any], bool]]:
    if adapter_id == "truenas-virt-incus-container":
        return {
            "query": ("virt.instance.query", [[["id", "=", name]]], False),
            "create": ("virt.instance.create", [], True),
            "update": ("virt.instance.update", [name], True),
            "start": ("virt.instance.start", [name], True),
            "stop": ("virt.instance.stop", [name, {"timeout": 30, "force": True}], True),
            "restart": ("virt.instance.restart", [name, {"timeout": 30, "force": True}], True),
            "delete": ("virt.instance.delete", [name], True),
        }
    if adapter_id == "truenas-container-lxc":
        if row_id is None:
            query = ("container.query", [[["name", "=", name]]], False)
            return {"query": query}
        return {
            "query": ("container.query", [[["name", "=", name]]], False),
            "create": ("container.create", [], True),
            "update": ("container.update", [row_id], False),
            "start": ("container.start", [row_id], False),
            "stop": ("container.stop", [row_id, {"force_after_timeout": True}], True),
            "delete": ("container.delete", [row_id], False),
        }
    raise ProbeError(f"unsupported container adapter: {adapter_id}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--registry", type=pathlib.Path, default=pathlib.Path("config/compute-materialization-targets.json"))
    p.add_argument("--target-version", required=True)
    p.add_argument("--name", default="rdte-compute-container-c0")
    p.add_argument("--nonce", default="agent-dispatch-container-c0-v1")
    p.add_argument("--legacy-image")
    p.add_argument("--image-name")
    p.add_argument("--image-version")
    p.add_argument("--pool")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--password-file", type=pathlib.Path)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=600.0)
    p.add_argument("--state-timeout", type=float, default=180.0)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--out", type=pathlib.Path)
    a = p.parse_args()

    receipt: dict[str, Any] = {
        "schema": "truenas-compute-container-c0/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "c0_oracle_satisfied": False,
        "c1_guest_oracle_satisfied": False,
        "target_version_requested": a.target_version,
        "name": a.name,
        "nonce": a.nonce,
        "states": [],
        "jobs": {},
        "cleanup": {"attempted": False, "absent": False},
        "claim_boundary": "C0 native API lifecycle only; guest-level C1 nonce/service oracle remains separately required",
    }
    ws = None
    call = None
    adapter_id = None
    row_id = None

    def emit() -> int:
        payload = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if a.out:
            a.out.write_text(payload, encoding="utf-8")
        print(payload, end="")
        return 0 if receipt.get("oracleSatisfied") else 2

    try:
        registry = load(a.registry)
        validate(registry)
        row = target(registry, "truenas", a.target_version)
        receipt["source_fingerprint"] = row["source_fingerprint"]
        receipt["api_schema_fingerprint"] = row["api_schema_fingerprint"]

        if not a.apply:
            receipt.update({
                "classification": "SUPPORTED",
                "oracleSatisfied": True,
                "phase": "plan-only",
                "detail": "C0 probe contract validated; apply was not requested",
                "apply_authorized": False,
            })
            return emit()

        if not a.port or not a.password_file:
            raise ProbeError("--apply requires --port and --password-file")
        password = a.password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise ProbeError("password file was empty")

        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise ProbeError(f"DDP connection failed: {connected!r}")
        request_id = 1

        def _call(method: str, params: list[Any]):
            nonlocal request_id
            result = ddp_call(ws, str(request_id), method, params)
            request_id += 1
            return result
        call = _call

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise ProbeError("authentication did not return SUCCESS")

        system_version = call("system.version", [])
        receipt["system_version"] = system_version
        exact = normalize_system_version(system_version)
        if exact != a.target_version:
            raise ProbeError(f"target mismatch: expected {a.target_version}, observed {exact}")

        method_map = call("core.get_methods", [])
        if not isinstance(method_map, dict):
            raise ProbeError("core.get_methods did not return a method map")
        adapter = choose_adapter(registry, "truenas", exact, "container", set(method_map))
        adapter_id = adapter["id"]
        receipt["adapter"] = adapter

        resolved_image, image_resolution = resolve_image_identity(
            adapter, call,
            legacy_image=a.legacy_image, image_name=a.image_name, image_version=a.image_version,
        )
        receipt["image_resolution"] = image_resolution
        create_payload = build_create_payload(
            adapter_id, a.name, a.nonce,
            pool=a.pool, **resolved_image,
        )
        receipt["desired_create"] = create_payload

        def query_one():
            shapes = method_shapes(adapter_id, a.name, row_id)
            method, params, _ = shapes["query"]
            rows = call(method, params)
            return rows[0] if isinstance(rows, list) and rows else None

        def wait_job(job_id: Any, label: str):
            if isinstance(job_id, bool) or not isinstance(job_id, int):
                raise ProbeError(f"{label} did not return job id: {job_id!r}")
            deadline = time.monotonic() + a.job_timeout
            while time.monotonic() < deadline:
                job = call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
                if job:
                    state = job.get("state")
                    if state == "SUCCESS":
                        receipt["jobs"][label] = {"id": job_id, "state": state}
                        return
                    if state in {"FAILED", "ABORTED"}:
                        raise ProbeError(f"{label} job {state}: {job.get('error') or job.get('exception')}")
                time.sleep(1)
            raise ProbeError(f"{label} job timeout")

        def invoke(label: str, params_tail: list[Any] | None = None):
            shapes = method_shapes(adapter_id, a.name, row_id)
            method, base, job_backed = shapes[label]
            params = list(base)
            if params_tail:
                params.extend(params_tail)
            result = call(method, params)
            if job_backed:
                wait_job(result, label)
            return result

        def wait_state(expected: str, label: str):
            deadline = time.monotonic() + a.state_timeout
            last = None
            while time.monotonic() < deadline:
                last = query_one()
                if observed_state(last) == expected:
                    receipt["states"].append({"label": label, "state": expected})
                    return last
                time.sleep(1)
            raise ProbeError(f"{label} did not reach {expected}: {last!r}")

        if query_one() is not None:
            raise ProbeError(f"preexisting instance {a.name!r} blocks ownership-safe apply")

        shapes = method_shapes(adapter_id, a.name)
        create_method = shapes.get("create", (adapter["required_methods"][1], [], True))[0]
        create_result = call(create_method, [create_payload])
        wait_job(create_result, "create")
        current = query_one()
        if not current:
            raise ProbeError("created container not observable")
        if adapter_id == "truenas-container-lxc":
            row_id = current.get("id")
            if not isinstance(row_id, int):
                raise ProbeError(f"26.x container id missing: {row_id!r}")
        receipt["states"].append({"label": "created", "state": observed_state(current)})

        invoke("start")
        wait_state("RUNNING", "start")

        invoke("stop")
        wait_state("STOPPED", "stop-before-update")

        invoke("update", [update_payload(adapter_id, a.nonce)])
        updated = query_one()
        if adapter_id == "truenas-virt-incus-container":
            if (updated or {}).get("environment", {}).get("RDTE_GENERATION") != "2":
                raise ProbeError("legacy environment update did not read back generation 2")
        else:
            if (updated or {}).get("initenv", {}).get("RDTE_GENERATION") != "2":
                raise ProbeError("LXC initenv update did not read back generation 2")
        receipt["update_readback"] = "RDTE_GENERATION=2"

        invoke("start")
        wait_state("RUNNING", "post-update-start")

        if adapter_id == "truenas-virt-incus-container":
            invoke("restart")
            wait_state("RUNNING", "restart")
        else:
            invoke("stop")
            wait_state("STOPPED", "restart-stop")
            invoke("start")
            wait_state("RUNNING", "restart-start")

        invoke("stop")
        wait_state("STOPPED", "final-stop")
        invoke("delete")
        deadline = time.monotonic() + a.state_timeout
        while time.monotonic() < deadline and query_one() is not None:
            time.sleep(1)
        receipt["cleanup"] = {"attempted": True, "absent": query_one() is None}
        if not receipt["cleanup"]["absent"]:
            raise ProbeError("container remained after delete")

        receipt.update({
            "classification": "SUPPORTED",
            "oracleSatisfied": True,
            "c0_oracle_satisfied": True,
            "phase": "c0-api-lifecycle",
            "detail": "native TrueNAS container API lifecycle, mutation readback and zero-residue cleanup passed",
        })
        return emit()
    except (ProbeError, ContractError, OSError, RuntimeError, ValueError) as exc:
        receipt["detail"] = f"{type(exc).__name__}: {exc}"
        if a.apply and call is not None and adapter_id:
            receipt["cleanup"]["attempted"] = True
            try:
                current = None
                shapes = method_shapes(adapter_id, a.name, row_id)
                qmethod, qparams, _ = shapes["query"]
                rows = call(qmethod, qparams)
                current = rows[0] if isinstance(rows, list) and rows else None
                if current:
                    if observed_state(current) == "RUNNING":
                        method, params, job_backed = shapes["stop"]
                        result = call(method, params)
                        if job_backed and isinstance(result, int) and not isinstance(result, bool):
                            # Bounded cleanup does not wait forever; the main evidence already records failure.
                            deadline = time.monotonic() + min(a.job_timeout, 60)
                            while time.monotonic() < deadline:
                                job = call("core.get_jobs", [[["id", "=", result]], {"get": True}])
                                if job and job.get("state") in {"SUCCESS", "FAILED", "ABORTED"}:
                                    break
                                time.sleep(1)
                    rows = call(qmethod, qparams)
                    current = rows[0] if isinstance(rows, list) and rows else None
                    if current:
                        if adapter_id == "truenas-container-lxc":
                            row_id = current.get("id")
                            shapes = method_shapes(adapter_id, a.name, row_id)
                        method, params, job_backed = shapes["delete"]
                        result = call(method, params)
                        if job_backed and isinstance(result, int) and not isinstance(result, bool):
                            deadline = time.monotonic() + min(a.job_timeout, 60)
                            while time.monotonic() < deadline:
                                job = call("core.get_jobs", [[["id", "=", result]], {"get": True}])
                                if job and job.get("state") in {"SUCCESS", "FAILED", "ABORTED"}:
                                    break
                                time.sleep(1)
                rows = call(qmethod, qparams)
                receipt["cleanup"]["absent"] = not rows
            except Exception as cleanup_exc:
                receipt["cleanup"]["error"] = f"{type(cleanup_exc).__name__}: {cleanup_exc}"
        return emit()
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
