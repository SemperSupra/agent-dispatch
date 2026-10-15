#!/usr/bin/env python3
"""Exact BETA.3 GARM Container pre-B4 runtime oracle.

Proves supported TrueNAS container.* realization, rootfs staging, one-shot init
execution, credential-file consumption, desired-state scrub, and zero residue.
It deliberately does not claim callback/JIT or GitHub registration.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import secrets
import time
import urllib.request

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


EXPECTED_SCHEMA = "semper-supra.garm-provider-truenas-container-pre-b4-fixture/3"
EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_DATASET_TEMPLATE = "{pool}/.truenas_containers/containers/{name}"
EXPECTED_MOUNTPOINT_TEMPLATE = "/.truenas_containers/{pool}/containers/{name}"
EXPECTED_ROOTFS_SOURCE = "src/middlewared/middlewared/plugins/container/utils.py"


class ProbeError(RuntimeError):
    pass


def is_explicit_not_found(exc: Exception) -> bool:
    text = str(exc).lower()
    return '"error": 2' in text or "enoent" in text or "not found" in text


def load_fixture(directory: pathlib.Path, producer: str) -> dict:
    p = directory / "garm-provider-container-pre-b4-fixture.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    if doc.get("schema") != EXPECTED_SCHEMA:
        raise ProbeError("unexpected Container fixture schema")
    if doc.get("producer_source") != producer:
        raise ProbeError("Container fixture producer drifted")
    target = doc.get("target") or {}
    if target.get("system_version") != EXPECTED_VERSION:
        raise ProbeError("fixture target drifted")
    if target.get("driver") != "container-v1" or target.get("control_surface") != "container.*":
        raise ProbeError("fixture driver drifted")
    if target.get("status") != "OPEN":
        raise ProbeError("fixture must remain non-admitted before runtime evidence")
    source_oracles = doc.get("source_oracles") or {}
    if source_oracles.get("runtime_admission_claimed") is not False:
        raise ProbeError("fixture illegally claims runtime admission")
    if source_oracles.get("source_derived_rootfs_projection_required") is not True:
        raise ProbeError("fixture does not require source-derived rootfs projection")
    required = set(target.get("required_methods") or [])
    if "pool.dataset.query" in required:
        raise ProbeError("fixture illegally reintroduced hidden-dataset query lowering")
    projection = doc.get("rootfs_projection") or {}
    if projection.get("dataset_template") != EXPECTED_DATASET_TEMPLATE:
        raise ProbeError("fixture dataset projection drifted")
    if projection.get("mountpoint_template") != EXPECTED_MOUNTPOINT_TEMPLATE:
        raise ProbeError("fixture mountpoint projection drifted")
    if projection.get("source_path") != EXPECTED_ROOTFS_SOURCE:
        raise ProbeError("fixture rootfs source path drifted")
    return doc


def derive_rootfs_mountpoint(fixture: dict, pool: str, name: str, dataset: str) -> str:
    projection = fixture.get("rootfs_projection") or {}
    expected_dataset = projection["dataset_template"].replace("{pool}", pool).replace("{name}", name)
    if dataset != expected_dataset:
        raise ProbeError(
            f"container dataset drifted from source projection: got {dataset!r}, expected {expected_dataset!r}"
        )
    mountpoint = projection["mountpoint_template"].replace("{pool}", pool).replace("{name}", name)
    if not mountpoint.startswith("/.truenas_containers/"):
        raise ProbeError(f"unsafe source-derived container mountpoint: {mountpoint!r}")
    return mountpoint


def multipart_upload(host: str, port: int, password: str, remote_path: str, content: bytes, mode: int) -> int:
    boundary = "----SemperSupra" + secrets.token_hex(12)
    data = json.dumps({
        "method": "filesystem.put",
        "params": [remote_path, {"append": False, "mode": mode}],
    }).encode()
    body = bytearray()
    def add(name: str, value: bytes, filename: str | None = None, content_type: str | None = None):
        body.extend(f"--{boundary}\r\n".encode())
        disp = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disp += f'; filename="{filename}"'
        body.extend((disp + "\r\n").encode())
        if content_type:
            body.extend((f"Content-Type: {content_type}\r\n").encode())
        body.extend(b"\r\n")
        body.extend(value)
        body.extend(b"\r\n")
    add("data", data)
    add("file", content, filename="payload", content_type="application/octet-stream")
    body.extend(f"--{boundary}--\r\n".encode())
    auth = base64.b64encode(f"truenas_admin:{password}".encode()).decode()
    req = urllib.request.Request(
        f"http://{host}:{port}/_upload/",
        data=bytes(body),
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "application/json",
            "User-Agent": "SemperSupra-GARM-Container-RDTE/1",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read().decode())
    job_id = result.get("job_id")
    if isinstance(job_id, bool) or not isinstance(job_id, int):
        raise ProbeError(f"filesystem.put upload did not return job id: {result!r}")
    return job_id


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--http-port", type=int, required=True)
    p.add_argument("--middleware-port", type=int, required=True)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--password-file", type=pathlib.Path, required=True)
    p.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    p.add_argument("--fixture-producer-commit", required=True)
    p.add_argument("--pool", required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=600.0)
    p.add_argument("--state-timeout", type=float, default=180.0)
    a = p.parse_args()

    started = time.time()
    receipt = {
        "schema": "truenas-garm-container-pre-b4-runtime/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "b0_b3_b5_pre_b4_complete": False,
        "bootstrap_execution_observed": False,
        "github_jit_boundary_claimed": False,
        "github_registration_exercised": False,
        "private_repository_execution": False,
        "physical_truenas_mutation": False,
        "per_runner_memory_isolation_claimed": False,
        "cleanup": {"attempted": False, "absent": False},
    }
    ws = None
    container_id = None
    container_name = None
    token = f"container-public-{secrets.token_hex(16)}"

    def emit(code: int) -> int:
        receipt["elapsed_seconds"] = round(time.time() - started, 3)
        a.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return code

    try:
        fixture = load_fixture(a.fixture_dir, a.fixture_producer_commit)
        receipt["fixture_producer_source"] = fixture["producer_source"]
        receipt["fixture_schema"] = fixture["schema"]
        receipt["target"] = fixture["target"]
        receipt["profile"] = fixture["profile"]
        container_name = fixture["expected_name"]

        password = a.password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise ProbeError("password file is empty")

        ws = WebSocket(a.host, a.middleware_port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise ProbeError(f"DDP connection failed: {connected!r}")
        request_id = 1
        def call(method: str, params: list):
            nonlocal request_id
            result = ddp_call(ws, str(request_id), method, params)
            request_id += 1
            return result

        auth = call("auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": "truenas_admin",
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise ProbeError("authentication did not return SUCCESS")

        version = call("system.version", [])
        receipt["system_version"] = version
        if version != EXPECTED_VERSION:
            raise ProbeError(f"exact version mismatch: {version!r}")

        methods = call("core.get_methods", [])
        required = set((fixture.get("target") or {}).get("required_methods") or [])
        missing = sorted(m for m in required if m not in methods)
        if missing:
            raise ProbeError(f"required middleware methods missing: {missing}")
        receipt["required_methods_present"] = True

        existing = call("container.query", [[["name", "=", container_name]]])
        if existing:
            raise ProbeError("preexisting named container blocks ownership-safe apply")

        images = call("container.image.query_registry", [])
        family = fixture["image_family"]
        image_row = next((x for x in images if isinstance(x, dict) and x.get("name") == family), None)
        if not image_row:
            raise ProbeError(f"image family unavailable: {family}")
        versions = [x.get("version") for x in (image_row.get("versions") or []) if isinstance(x, dict) and x.get("version")]
        if not versions:
            raise ProbeError("image family returned no exact versions")
        image_version = versions[-1]
        receipt["image"] = {"name": family, "version": image_version}

        desired = fixture["desired_create"]
        create_payload = {
            "name": container_name,
            "description": desired["description"],
            "autostart": False,
            "idmap": {"type": desired["idmap_type"]},
            "capabilities_policy": desired["capabilities_policy"],
            "init": desired["init"],
            "initenv": dict(desired["initenv"]),
            "pool": a.pool,
            "image": {"name": family, "version": image_version},
        }
        if token in json.dumps(create_payload):
            raise ProbeError("runtime credential leaked into container.create payload")

        create_job = call("container.create", [create_payload])
        if isinstance(create_job, bool) or not isinstance(create_job, int):
            raise ProbeError(f"container.create did not return job id: {create_job!r}")

        def wait_job(job_id: int, label: str):
            deadline = time.monotonic() + a.job_timeout
            while time.monotonic() < deadline:
                job = call("core.get_jobs", [[["id", "=", job_id]], {"get": True}])
                if job:
                    state = job.get("state")
                    if state == "SUCCESS":
                        return job
                    if state in {"FAILED", "ABORTED"}:
                        raise ProbeError(f"{label} {state}: {job.get('error') or job.get('exception')}")
                time.sleep(1)
            raise ProbeError(f"{label} timed out")

        wait_job(create_job, "container.create")
        rows = call("container.query", [[["name", "=", container_name]]])
        if len(rows) != 1:
            raise ProbeError("created container did not read back exactly once")
        row = rows[0]
        container_id = row.get("id")
        if not isinstance(container_id, int):
            raise ProbeError("created container has no integer id")
        if (row.get("status") or {}).get("state") != "STOPPED":
            raise ProbeError("container was not STOPPED before staging")
        if row.get("init") != desired["init"] or row.get("initenv") != desired["initenv"]:
            raise ProbeError("bootstrap desired state did not read back exactly")

        dataset = row.get("dataset")
        if not isinstance(dataset, str) or not dataset:
            raise ProbeError("container dataset identity missing")
        mountpoint = derive_rootfs_mountpoint(fixture, a.pool, container_name, dataset)
        receipt["dataset"] = dataset
        receipt["mountpoint"] = mountpoint
        receipt["rootfs_projection_source"] = fixture["rootfs_projection"]["source_path"]

        staged = []
        for spec in fixture["staged_files"]:
            rel = spec["path"]
            remote = mountpoint.rstrip("/") + rel
            contains_secret = bool(spec["contains_secret"])
            content = token.encode() if contains_secret else spec["content"].encode()
            if not contains_secret:
                got_sha = hashlib.sha256(content).hexdigest()
                if got_sha != spec["sha256"]:
                    raise ProbeError(f"fixture staged-file digest drift: {rel}")
            job_id = multipart_upload(a.host, a.http_port, password, remote, content, int(spec["mode"]))
            wait_job(job_id, f"filesystem.put {rel}")
            stat = call("filesystem.stat", [remote])
            if stat.get("size") != len(content) or (int(stat.get("mode", 0)) & 0o777) != int(spec["mode"]):
                raise ProbeError(f"staged-file readback drift: {rel}")
            staged.append({"path": rel, "mode": int(spec["mode"]), "contains_secret": contains_secret})
        receipt["staged_files"] = staged

        call("container.start", [container_id])
        deadline = time.monotonic() + a.state_timeout
        while time.monotonic() < deadline:
            rows = call("container.query", [[["id", "=", container_id]]])
            if rows and (rows[0].get("status") or {}).get("state") == "RUNNING":
                break
            time.sleep(1)
        else:
            raise ProbeError("container did not reach RUNNING")

        marker_stats = {}
        for marker in fixture["execution_markers"]:
            remote = mountpoint.rstrip("/") + marker
            deadline = time.monotonic() + 45
            stat = None
            while time.monotonic() < deadline:
                try:
                    stat = call("filesystem.stat", [remote])
                    break
                except Exception:
                    time.sleep(1)
            if not stat:
                raise ProbeError(f"execution marker not observed: {marker}")
            marker_stats[marker] = {"size": stat.get("size"), "mode": stat.get("mode")}
        receipt["execution_markers"] = marker_stats
        receipt["bootstrap_execution_observed"] = True

        token_path = mountpoint.rstrip("/") + "/var/lib/garm-container/bootstrap-instance-token"
        try:
            call("filesystem.stat", [token_path])
        except RuntimeError as exc:
            if not is_explicit_not_found(exc):
                raise ProbeError(f"credential-file absence could not be proven: {exc}") from exc
        else:
            raise ProbeError("one-shot credential file remained after wrapper consumption")
        receipt["credential_file_deleted"] = True

        expected_post = fixture["expected_post_start"]
        updated = call("container.update", [container_id, {
            "init": expected_post["init"],
            "initenv": expected_post["initenv"],
        }])
        if not isinstance(updated, dict):
            rows = call("container.query", [[["id", "=", container_id]]])
            updated = rows[0] if rows else None
        if not isinstance(updated, dict) or updated.get("init") != expected_post["init"] or updated.get("initenv") != expected_post["initenv"]:
            raise ProbeError("post-start desired-state scrub did not read back")
        receipt["desired_state_scrubbed"] = True

        stop_job = call("container.stop", [container_id, {"force_after_timeout": True}])
        if isinstance(stop_job, int) and not isinstance(stop_job, bool):
            wait_job(stop_job, "container.stop")
        call("container.delete", [container_id])
        deadline = time.monotonic() + a.state_timeout
        while time.monotonic() < deadline:
            rows = call("container.query", [[["id", "=", container_id]]])
            if not rows:
                break
            time.sleep(1)
        rows = call("container.query", [[["name", "=", container_name]]])
        if rows:
            raise ProbeError("container remains after delete")
        receipt["cleanup"] = {"attempted": True, "absent": True}

        receipt.update({
            "classification": "SUPPORTED",
            "oracleSatisfied": True,
            "b0_b3_b5_pre_b4_complete": True,
            "detail": (
                "exact BETA.3 container.* candidate completed source/method validation, "
                "stopped creation, supported rootfs staging, wrapper/bootstrap-child execution "
                "markers, one-shot credential-file consumption, desired init/env scrub, "
                "stop/delete and zero-residue absence; callback/JIT remains a separate B4 gate"
            ),
        })
        return emit(0)
    except Exception as exc:
        receipt["detail"] = f"{type(exc).__name__}: {str(exc).replace(token, '<runtime-token>')}"
        if ws is not None and container_id is not None:
            receipt["cleanup"]["attempted"] = True
            try:
                request_id = locals().get("request_id", 1)
                def cleanup_call(method: str, params: list):
                    nonlocal request_id
                    result = ddp_call(ws, str(request_id), method, params)
                    request_id += 1
                    return result
                rows = cleanup_call("container.query", [[["id", "=", container_id]]])
                if rows and (rows[0].get("status") or {}).get("state") == "RUNNING":
                    result = cleanup_call("container.stop", [container_id, {"force": True}])
                    if isinstance(result, int) and not isinstance(result, bool):
                        deadline = time.monotonic() + 60
                        while time.monotonic() < deadline:
                            job = cleanup_call("core.get_jobs", [[["id", "=", result]], {"get": True}])
                            if job and job.get("state") in {"SUCCESS", "FAILED", "ABORTED"}:
                                break
                            time.sleep(1)
                cleanup_call("container.delete", [container_id])
                rows = cleanup_call("container.query", [[["name", "=", container_name]]])
                receipt["cleanup"]["absent"] = not rows
            except Exception as cleanup_exc:
                receipt["cleanup"]["error"] = f"{type(cleanup_exc).__name__}: {cleanup_exc}"
        return emit(2)
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
