#!/usr/bin/env python3
"""Exact TrueNAS 26 BETA.3 GARM system-container pre-B4 oracle.

This probe intentionally stops before GitHub/JIT admission. It proves only the
provider-owned container-v1 lifecycle, supported rootfs staging, execution
markers, persisted desired-state scrub, one-shot credential-file deletion and
zero-residue retirement.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import secrets
import ssl
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from truenas_middleware_garm_provider_g2_probe import AdminSession

EXPECTED_SCHEMA = "semper-supra.garm-provider-truenas-container-pre-b4-fixture/3"
EXPECTED_VERSION = "TrueNAS-26.0.0-BETA.3"
EXPECTED_MIDDLEWARE = "81e1265a86083888ba94a2bdfc02ff5c9c5ef6a3"
EXPECTED_DRIVER = "container-v1"
EXPECTED_CONTROL = "container.*"
TOKEN_PLACEHOLDER = "__RUN_LOCAL_INSTANCE_TOKEN__"
TOKEN_PATH = "/var/lib/garm-container/bootstrap-instance-token"
INIT_MARKER = "/var/lib/garm-container/init-wrapper-executed"
CHILD_MARKER = "/var/lib/garm-container/bootstrap-child-started"

class ProbeError(RuntimeError):
    pass

def canonical_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def load_fixture(directory: pathlib.Path, expected_producer: str) -> dict[str, Any]:
    path = directory / "garm-provider-container-pre-b4-fixture.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != EXPECTED_SCHEMA:
        raise ProbeError("unexpected Container pre-B4 fixture schema")
    if doc.get("producer_source") != expected_producer:
        raise ProbeError("fixture producer source drifted")
    target = doc.get("target") or {}
    if target.get("system_version") != EXPECTED_VERSION:
        raise ProbeError("fixture target version drifted")
    if target.get("middleware_commit") != EXPECTED_MIDDLEWARE:
        raise ProbeError("fixture middleware identity drifted")
    if target.get("driver") != EXPECTED_DRIVER or target.get("control_surface") != EXPECTED_CONTROL:
        raise ProbeError("fixture driver/control surface drifted")
    if target.get("status") != "OPEN":
        raise ProbeError("fixture unexpectedly claims runtime admission")
    desired = doc.get("desired_create") or {}
    env = desired.get("initenv") or {}
    if "GARM_INSTANCE_TOKEN" in env:
        raise ProbeError("fixture create arguments contain a credential placeholder")
    if env.get("RUNNER_ALLOW_RUNASROOT") != "1":
        raise ProbeError("fixture system-container root execution boundary disappeared")
    staged = doc.get("staged_files")
    if not isinstance(staged, list) or len(staged) != 3:
        raise ProbeError("fixture staged-file inventory drifted")
    secret = [x for x in staged if isinstance(x, dict) and x.get("contains_secret") is True]
    if len(secret) != 1:
        raise ProbeError("fixture must contain exactly one credential-bearing staged file")
    if secret[0].get("path") != TOKEN_PATH or secret[0].get("mode") != 0o600:
        raise ProbeError("fixture credential-file path/mode drifted")
    if secret[0].get("content") != TOKEN_PLACEHOLDER:
        raise ProbeError("public fixture contains an unexpected credential value")
    for item in staged:
        if not isinstance(item, dict):
            raise ProbeError("invalid staged-file entry")
        if item.get("contains_secret") is not True:
            raw = str(item.get("content", "")).encode()
            if item.get("sha256") != canonical_sha256(raw):
                raise ProbeError(f"staged file digest drifted: {item.get('path')}")
    markers = doc.get("execution_markers")
    if markers != [INIT_MARKER, CHILD_MARKER]:
        raise ProbeError("execution-marker contract drifted")
    oracles = doc.get("source_oracles") or {}
    for key in (
        "supported_rootfs_staging_defined",
        "create_arguments_credential_free",
        "credential_pipe_staging_required",
        "credential_file_delete_required",
        "temporary_init_scrub_required",
        "runner_root_under_default_idmap_explicit",
        "external_restart_forbidden",
        "active_delete_refused",
        "final_absence_required",
    ):
        if oracles.get(key) is not True:
            raise ProbeError(f"required source oracle is not true: {key}")
    for key in (
        "per_runner_memory_isolation_claimed",
        "runtime_admission_claimed",
        "bootstrap_execution_claimed",
        "github_jit_boundary_claimed",
    ):
        if oracles.get(key) is not False:
            raise ProbeError(f"forbidden source claim is not false: {key}")
    return doc

def multipart_body(data_json: str, filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----SemperSupra" + uuid.uuid4().hex
    b = boundary.encode()
    body = bytearray()
    body += b"--" + b + b"\r\n"
    body += b'Content-Disposition: form-data; name="data"\r\n\r\n'
    body += data_json.encode() + b"\r\n"
    body += b"--" + b + b"\r\n"
    body += f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += content + b"\r\n"
    body += b"--" + b + b"--\r\n"
    return bytes(body), boundary

def upload_file(
    host: str,
    port: int,
    username: str,
    password: str,
    remote_path: str,
    content: bytes,
    mode: int,
    timeout: float,
) -> int:
    data = json.dumps({
        "method": "filesystem.put",
        "params": [remote_path, {"append": False, "mode": mode}],
    }, separators=(",", ":"))
    body, boundary = multipart_body(data, pathlib.PurePosixPath(remote_path).name, content)
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = urllib.request.Request(
        f"http://{host}:{port}/_upload/",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "User-Agent": "SemperSupra-GARM-Container-PreB4/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=max(timeout, 30.0)) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read(2048).decode(errors="replace")
        raise ProbeError(f"filesystem.put upload failed HTTP {exc.code}: {detail}") from exc
    job_id = payload.get("job_id") if isinstance(payload, dict) else None
    if isinstance(job_id, bool) or not isinstance(job_id, int):
        raise ProbeError("filesystem.put upload did not return a job id")
    return job_id

def state(row: dict[str, Any] | None) -> str:
    if not row:
        return "ABSENT"
    value = row.get("status")
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("state"), str):
        return value["state"]
    return "UNKNOWN"

def image_version(session: AdminSession, family: str) -> str:
    rows = session.call("container.image.query_registry", [])
    if not isinstance(rows, list):
        raise ProbeError("container.image.query_registry did not return an array")
    row = next((x for x in rows if isinstance(x, dict) and x.get("name") == family), None)
    if not row:
        raise ProbeError(f"required image family unavailable: {family}")
    versions = [
        x.get("version") for x in (row.get("versions") or [])
        if isinstance(x, dict) and isinstance(x.get("version"), str) and x.get("version")
    ]
    if not versions:
        raise ProbeError("required image family has no exact versions")
    return versions[-1]

def query_one(session: AdminSession, name: str) -> dict[str, Any] | None:
    rows = session.call("container.query", [[["name", "=", name]]])
    if not isinstance(rows, list):
        raise ProbeError("container.query did not return an array")
    return rows[0] if rows else None

def wait_state(session: AdminSession, name: str, expected: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = query_one(session, name)
        if state(last) == expected:
            return last
        time.sleep(1)
    raise ProbeError(f"container did not reach {expected}: {last!r}")

def dataset_mountpoint(session: AdminSession, dataset: str) -> str:
    rows = session.call("pool.dataset.query", [[["id", "=", dataset]]])
    if not isinstance(rows, list) or len(rows) != 1:
        raise ProbeError(f"owned root dataset lookup drifted: {dataset!r}")
    mount = rows[0].get("mountpoint")
    if isinstance(mount, dict):
        mount = mount.get("value") or mount.get("rawvalue")
    if not isinstance(mount, str) or not mount.startswith("/mnt/"):
        raise ProbeError(f"unsafe root dataset mountpoint: {mount!r}")
    return mount.rstrip("/")

def stat_file(session: AdminSession, path: str) -> dict[str, Any] | None:
    try:
        value = session.call("filesystem.stat", [path])
    except RuntimeError as exc:
        text = str(exc).lower()
        if "enoent" in text or "not found" in text or "no such file" in text:
            return None
        raise
    return value if isinstance(value, dict) else None

def wait_file(session: AdminSession, path: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = stat_file(session, path)
        if value is not None:
            return value
        time.sleep(1)
    raise ProbeError(f"execution marker did not appear: {path}")

def delete_owned(session: AdminSession, name: str, timeout: float) -> None:
    row = query_one(session, name)
    if row is None:
        return
    row_id = row.get("id")
    if not isinstance(row_id, int):
        raise ProbeError("owned container has no numeric id during cleanup")
    if state(row) == "RUNNING":
        job_id = session.call("container.stop", [row_id, {"force_after_timeout": True}])
        if isinstance(job_id, int) and not isinstance(job_id, bool):
            session.wait_job(job_id, "container.stop cleanup", timeout)
        wait_state(session, name, "STOPPED", timeout)
    session.call("container.delete", [row_id])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if query_one(session, name) is None:
            return
        time.sleep(1)
    raise ProbeError("owned container remained after delete")

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--http-port", type=int, required=True)
    p.add_argument("--password-file", type=pathlib.Path, required=True)
    p.add_argument("--fixture-dir", type=pathlib.Path, required=True)
    p.add_argument("--fixture-producer-commit", required=True)
    p.add_argument("--expected-middleware-commit", default=EXPECTED_MIDDLEWARE)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=300.0)
    p.add_argument("--state-timeout", type=float, default=180.0)
    a = p.parse_args()

    receipt: dict[str, Any] = {
        "schema": "truenas-garm-container-pre-b4/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "runtime_admission": False,
        "github_credentials_present": False,
        "github_jit_registration_exercised": False,
        "private_repository_execution": False,
        "physical_truenas_mutation": False,
        "per_runner_memory_isolation_claimed": False,
        "direct_incus_or_lxc_bypass": False,
        "private_nsenter_used": False,
        "credential_recorded": False,
        "cleanup": {"attempted": False, "container_absent": False, "dataset_absent": False},
    }
    session = None
    fixture = None
    name = None
    root_dataset = None
    runtime_token = f"preb4-{secrets.token_hex(16)}"
    started = time.time()

    def emit() -> int:
        raw = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if runtime_token in raw:
            raise ProbeError("runtime credential leaked into durable receipt")
        a.out.write_text(raw, encoding="utf-8")
        print(raw, end="")
        return 0 if receipt.get("oracleSatisfied") else 2

    try:
        if a.expected_middleware_commit != EXPECTED_MIDDLEWARE:
            raise ProbeError("requested middleware identity does not match probe contract")
        fixture = load_fixture(a.fixture_dir, a.fixture_producer_commit)
        receipt["fixture_producer_source"] = a.fixture_producer_commit
        receipt["middleware_commit"] = EXPECTED_MIDDLEWARE
        receipt["fixture_sha256"] = canonical_sha256(
            (a.fixture_dir / "garm-provider-container-pre-b4-fixture.json").read_bytes()
        )
        name = fixture["expected_name"]
        password = a.password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise ProbeError("TrueNAS admin password file is empty")

        session = AdminSession(a.host, a.http_port, password, a.timeout)
        session.connect()
        observed_version = session.call("system.version", [])
        receipt["system_version"] = observed_version
        if observed_version != EXPECTED_VERSION:
            raise ProbeError(f"system.version drifted: {observed_version!r}")

        methods = session.call("core.get_methods", [])
        if not isinstance(methods, dict):
            raise ProbeError("core.get_methods did not return a map")
        required = set(fixture["target"].get("required_methods") or [])
        missing = sorted(required - set(methods))
        if missing:
            raise ProbeError(f"required public middleware methods missing: {missing}")
        receipt["required_methods_observed"] = sorted(required)

        if query_one(session, name) is not None:
            raise ProbeError("preexisting container blocks ownership-safe apply")

        family = fixture["image_family"]
        exact_image_version = image_version(session, family)
        receipt["image"] = {"name": family, "version": exact_image_version}

        desired = fixture["desired_create"]
        create_env = dict(desired["initenv"])
        if "GARM_INSTANCE_TOKEN" in create_env:
            raise ProbeError("credential appeared in create desired state")
        create_payload = {
            "name": name,
            "description": desired["description"],
            "autostart": False,
            "time": "UTC",
            "init": desired["init"],
            "initenv": create_env,
            "idmap": {"type": "DEFAULT"},
            "capabilities_policy": "DEFAULT",
            "image": {"name": family, "version": exact_image_version},
        }
        create_job = session.call("container.create", [create_payload])
        if not isinstance(create_job, int) or isinstance(create_job, bool):
            raise ProbeError(f"container.create did not return a job id: {create_job!r}")
        session.wait_job(create_job, "container.create", a.job_timeout)

        row = query_one(session, name)
        if row is None or state(row) != "STOPPED":
            raise ProbeError(f"created container did not remain STOPPED: {row!r}")
        row_id = row.get("id")
        if not isinstance(row_id, int):
            raise ProbeError("created container did not expose numeric id")
        root_dataset = row.get("dataset")
        if not isinstance(root_dataset, str) or not root_dataset:
            raise ProbeError("created container did not expose root dataset")
        if row.get("autostart") is not False:
            raise ProbeError("autostart drifted")
        if (row.get("idmap") or {}).get("type") != "DEFAULT":
            raise ProbeError("idmap drifted from DEFAULT")
        if row.get("capabilities_policy") != "DEFAULT":
            raise ProbeError("capabilities policy drifted")
        if row.get("init") != desired["init"] or row.get("initenv") != create_env:
            raise ProbeError("temporary bootstrap desired state read-back drifted")
        if runtime_token in json.dumps(row, sort_keys=True):
            raise ProbeError("runtime credential leaked into container query state")
        mountpoint = dataset_mountpoint(session, root_dataset)
        receipt["owned_root_dataset"] = root_dataset
        receipt["root_mountpoint_observed"] = True

        staged_receipt = []
        for item in fixture["staged_files"]:
            relative = pathlib.PurePosixPath(str(item["path"]))
            if not relative.is_absolute() or ".." in relative.parts:
                raise ProbeError(f"unsafe fixture path: {relative}")
            remote = mountpoint + str(relative)
            raw_content = str(item["content"])
            if item.get("contains_secret") is True:
                if raw_content != TOKEN_PLACEHOLDER or item.get("path") != TOKEN_PATH:
                    raise ProbeError("unexpected credential fixture")
                content = runtime_token.encode()
            else:
                content = raw_content.encode()
            job_id = upload_file(
                a.host, a.http_port, "truenas_admin", password,
                remote, content, int(item["mode"]), a.timeout,
            )
            session.wait_job(job_id, f"filesystem.put {item['path']}", a.job_timeout)
            observed = stat_file(session, remote)
            if observed is None:
                raise ProbeError(f"staged file absent after upload: {item['path']}")
            if observed.get("size") != len(content) or int(observed.get("mode", 0)) & 0o777 != int(item["mode"]):
                raise ProbeError(f"staged file stat drifted: {item['path']}")
            staged_receipt.append({
                "path": item["path"],
                "mode": item["mode"],
                "size": len(content),
                "contains_credential": item.get("contains_secret") is True,
                "sha256": None if item.get("contains_secret") is True else canonical_sha256(content),
            })
        receipt["staged_files"] = staged_receipt

        session.call("container.start", [row_id])
        row = wait_state(session, name, "RUNNING", a.state_timeout)

        expected_post = fixture["expected_post_start"]
        session.call("container.update", [row_id, {
            "init": expected_post["init"],
            "initenv": expected_post["initenv"],
        }])
        row = query_one(session, name)
        if row is None or row.get("init") != "/sbin/init" or (row.get("initenv") or {}) != {}:
            raise ProbeError("post-start desired init/environment scrub did not read back exactly")
        receipt["desired_state_scrubbed"] = True

        marker_stats = {}
        for marker in fixture["execution_markers"]:
            observed = wait_file(session, mountpoint + marker, a.state_timeout)
            marker_stats[marker] = {"size": observed.get("size"), "mode": int(observed.get("mode", 0)) & 0o777}
        receipt["execution_markers"] = marker_stats

        if stat_file(session, mountpoint + TOKEN_PATH) is not None:
            raise ProbeError("one-shot credential file remains after init-wrapper execution")
        receipt["credential_file_absent"] = True

        # Prove /sbin/init remained alive after wrapper replacement; no private
        # shell/nsenter primitive is used.
        time.sleep(3)
        row = query_one(session, name)
        if row is None or state(row) != "RUNNING":
            raise ProbeError("container did not remain RUNNING after init-wrapper handoff")
        receipt["systemd_running_after_wrapper"] = True

        stop_job = session.call("container.stop", [row_id, {"force_after_timeout": True}])
        if isinstance(stop_job, int) and not isinstance(stop_job, bool):
            session.wait_job(stop_job, "container.stop", a.job_timeout)
        wait_state(session, name, "STOPPED", a.state_timeout)

        session.call("container.delete", [row_id])
        deadline = time.monotonic() + a.state_timeout
        while time.monotonic() < deadline and query_one(session, name) is not None:
            time.sleep(1)
        if query_one(session, name) is not None:
            raise ProbeError("container remains after delete")
        datasets = session.call("pool.dataset.query", [[["id", "=", root_dataset]]])
        if datasets:
            raise ProbeError("owned root dataset remains after container delete")

        receipt["cleanup"] = {"attempted": True, "container_absent": True, "dataset_absent": True}
        receipt["classification"] = "SUPPORTED"
        receipt["oracleSatisfied"] = True
        receipt["pre_b4_complete"] = True
        receipt["detail"] = (
            "exact BETA.3 container-v1 pre-B4 lifecycle passed stopped create, "
            "credential-free desired state, supported filesystem.put/stat rootfs staging, "
            "init-wrapper and bootstrap-child execution markers, post-start init/env scrub, "
            "one-shot credential-file deletion, sustained RUNNING state, stopped retirement, "
            "container absence, root-dataset absence and zero residue; GitHub/JIT/runtime "
            "admission and per-runner memory-isolation claims remain explicitly unexercised"
        )
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}".replace(runtime_token, "<runtime-credential>")
        receipt["detail"] = detail
    finally:
        if session is not None and name:
            receipt["cleanup"]["attempted"] = True
            try:
                delete_owned(session, name, min(a.job_timeout, 90.0))
                receipt["cleanup"]["container_absent"] = query_one(session, name) is None
                if root_dataset:
                    datasets = session.call("pool.dataset.query", [[["id", "=", root_dataset]]])
                    receipt["cleanup"]["dataset_absent"] = not bool(datasets)
            except Exception as cleanup_exc:
                receipt["cleanup"]["error"] = (
                    f"{type(cleanup_exc).__name__}: {cleanup_exc}"
                ).replace(runtime_token, "<runtime-credential>")
            session.close()
        receipt["elapsed_seconds"] = round(time.time() - started, 3)

    return emit()

if __name__ == "__main__":
    raise SystemExit(main())
