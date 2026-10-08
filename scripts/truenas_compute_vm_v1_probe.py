#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import pathlib
import ssl
import time
from typing import Any

from scripts.compute_guest_seed import NONCE_RE, SeedError, validate_token
from scripts.truenas_compute_vm_probe import native_vm_create_payload, normalize_system_version
from scripts.truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for
from scripts.truenas_vm_console_probe import observe_console_nonce

PINNED_CIRROS_SHA256 = "7d6355852aeb6dbcd191bcda7cd74f1536cfe5cbf8a10495a7283a8396e4b75b"


class V1ProbeError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stage_paths(pool: str, stem: str = "rdtev1") -> dict[str, str]:
    if not pool or "/" in pool or not pool.replace("_", "").isalnum():
        raise V1ProbeError("pool name violates V1 staging contract")
    dataset = f"{pool}/{stem}stage"
    mount = f"/mnt/{dataset}"
    boot_zvol = f"{pool}/{stem}boot"
    return {
        "dataset": dataset,
        "raw_image": f"{mount}/cirros-0.6.3-x86_64.raw",
        "seed_iso": f"{mount}/seed.iso",
        "boot_zvol": boot_zvol,
        "boot_zvol_path": f"/dev/zvol/{boot_zvol}",
    }


def zvol_boot_device(vm_id: int, zvol_name: str, size_bytes: int = 1024 * 1024 * 1024) -> dict[str, Any]:
    if not zvol_name or "/" not in zvol_name:
        raise V1ProbeError("V1 boot ZVOL name must include pool prefix")
    return {
        "vm": vm_id,
        "attributes": {
            "dtype": "DISK",
            "path": None,
            "type": "VIRTIO",
            "create_zvol": True,
            "zvol_name": zvol_name,
            "zvol_volsize": size_bytes,
        },
        "order": 100,
    }


def seed_cdrom_device(vm_id: int, path: str) -> dict[str, Any]:
    return {
        "vm": vm_id,
        "attributes": {"dtype": "CDROM", "path": path},
        "order": 1000,
    }


def multipart_upload_body(remote_path: str, filename: str, content: bytes, boundary: str) -> bytes:
    request = json.dumps(
        {"method": "filesystem.put", "params": [remote_path]},
        separators=(",", ":"),
    ).encode()
    parts = [
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="data"\r\n'
        b"Content-Type: application/json\r\n\r\n" + request + b"\r\n",
        b"--" + boundary.encode() + b"\r\n"
        + f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
        + b"Content-Type: application/octet-stream\r\n\r\n"
        + content + b"\r\n",
        b"--" + boundary.encode() + b"--\r\n",
    ]
    return b"".join(parts)


def upload_file(host: str, port: int, username: str, password: str, local: pathlib.Path,
                remote: str, tls: bool, timeout: float) -> int:
    boundary = "agentdispatchv1upload"
    body = multipart_upload_body(remote, local.name, local.read_bytes(), boundary)
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            "/_upload/",
            body=body,
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
            },
        )
        response = conn.getresponse()
        payload = response.read()
        if response.status // 100 != 2:
            raise V1ProbeError(f"filesystem.put upload HTTP {response.status}: {payload[:1000]!r}")
        decoded = json.loads(payload.decode())
        job_id = decoded.get("job_id")
        if not isinstance(job_id, int) or isinstance(job_id, bool):
            raise V1ProbeError(f"filesystem.put upload returned invalid job id: {decoded!r}")
        return job_id
    finally:
        conn.close()


def wait_job(ws: WebSocket, job_id: int, timeout: float, label: str) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = ddp_call(ws, f"job-{label}-{job_id}", "core.get_jobs", [[["id", "=", job_id]], {"get": True}])
        if row and row.get("state") == "SUCCESS":
            return row.get("result")
        if row and row.get("state") in {"FAILED", "ABORTED"}:
            raise V1ProbeError(f"{label} job {row.get('state')}: {row.get('error') or row.get('exception')}")
        time.sleep(1)
    raise V1ProbeError(f"{label} job timed out")


def plan(pool: str, name: str, nonce: str) -> dict[str, Any]:
    validate_token(nonce, NONCE_RE, "nonce")
    paths = stage_paths(pool)
    return {
        "schema": "truenas-compute-vm-v1-plan/v1",
        "name": name,
        "staging": paths,
        "vm_create": native_vm_create_payload(name),
        "devices": [
            zvol_boot_device(0, paths["boot_zvol"]),
            seed_cdrom_device(0, paths["seed_iso"]),
        ],
        "media_lowering": {
            "source": paths["raw_image"],
            "destination": paths["boot_zvol_path"],
            "method": "vm.device.convert",
        },
        "oracle": {
            "surface": "/websocket/shell",
            "nonce": f"AGENT_DISPATCH_V1_NONCE={nonce}",
        },
        "claim_boundary": "pinned Linux guest boot + exact external nonce only",
    }


def run_apply(a: argparse.Namespace) -> dict[str, Any]:
    validate_token(a.nonce, NONCE_RE, "nonce")
    source_sha = sha256_file(a.source_image)
    if source_sha != PINNED_CIRROS_SHA256:
        raise V1ProbeError(f"source CirrOS digest mismatch: {source_sha}")
    raw_sha = sha256_file(a.raw_image)
    seed_sha = sha256_file(a.seed_iso)
    password = a.password_file.read_text(encoding="utf-8").strip()
    paths = stage_paths(a.pool)
    receipt: dict[str, Any] = {
        "schema": "truenas-compute-vm-v1/v1",
        "classification": "ORACLE_FAILURE",
        "oracleSatisfied": False,
        "v1_oracle_satisfied": False,
        "source": {
            "cirros_release": "0.6.3",
            "cirros_sha256": source_sha,
            "converted_raw_sha256": raw_sha,
            "seed_iso_sha256": seed_sha,
        },
        "staging": paths,
        "cleanup": {
            "attempted": False,
            "vm_absent": False,
            "boot_zvol_absent": False,
            "staging_dataset_absent": False,
        },
        "claim_boundary": "V1 Linux guest boot + exact external nonce only; nested KVM, Firecracker and Windows remain separate",
    }
    ws: WebSocket | None = None
    vm_id: int | None = None
    boot_device_id: int | None = None
    stage_owned = False
    try:
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise V1ProbeError(f"DDP connection failed: {connected!r}")
        auth = ddp_call(ws, "auth", "auth.login_ex", [{
            "mechanism": "PASSWORD_PLAIN",
            "username": a.username,
            "password": password,
        }])
        if not isinstance(auth, dict) or auth.get("response_type") != "SUCCESS":
            raise V1ProbeError(f"authentication failed: {auth!r}")
        version = normalize_system_version(ddp_call(ws, "version", "system.version", []))
        if version != a.target_version:
            raise V1ProbeError(f"target version mismatch: observed={version} expected={a.target_version}")

        if ddp_call(ws, "pre-vm", "vm.query", [[["name", "=", a.name]]]):
            raise V1ProbeError(f"preexisting VM {a.name!r} blocks ownership-safe V1")
        if ddp_call(ws, "pre-stage", "pool.dataset.query", [[["id", "=", paths["dataset"]]]]):
            raise V1ProbeError(f"preexisting staging dataset {paths['dataset']!r} blocks ownership-safe V1")
        if ddp_call(ws, "pre-boot-zvol", "pool.dataset.query", [[["id", "=", paths["boot_zvol"]]]]):
            raise V1ProbeError(f"preexisting boot ZVOL {paths['boot_zvol']!r} blocks ownership-safe V1")

        ddp_call(ws, "mk-stage", "pool.dataset.create", [{
            "name": paths["dataset"], "type": "FILESYSTEM", "exec": "OFF", "share_type": "GENERIC",
        }])
        stage_owned = True

        upload_job = upload_file(a.host, a.port, a.username, password, a.raw_image, paths["raw_image"], a.tls, a.timeout)
        wait_job(ws, upload_job, a.job_timeout, "upload-raw")
        upload_job = upload_file(a.host, a.port, a.username, password, a.seed_iso, paths["seed_iso"], a.tls, a.timeout)
        wait_job(ws, upload_job, a.job_timeout, "upload-seed")
        for label, path in (("raw", paths["raw_image"]), ("seed", paths["seed_iso"])):
            stat = ddp_call(ws, f"stat-{label}", "filesystem.stat", [path])
            if not isinstance(stat, dict) or stat.get("type") != "FILE":
                raise V1ProbeError(f"uploaded {label} media not observable through filesystem.stat: {stat!r}")

        vm = ddp_call(ws, "vm-create", "vm.create", [native_vm_create_payload(a.name)])
        if not isinstance(vm, dict) or not isinstance(vm.get("id"), int):
            raise V1ProbeError(f"vm.create returned invalid VM: {vm!r}")
        vm_id = vm["id"]
        boot = zvol_boot_device(vm_id, paths["boot_zvol"])
        seed = seed_cdrom_device(vm_id, paths["seed_iso"])
        created_boot = ddp_call(ws, "boot-device", "vm.device.create", [boot])
        if not isinstance(created_boot, dict) or not isinstance(created_boot.get("id"), int):
            raise V1ProbeError(f"boot DISK/ZVOL create returned invalid device: {created_boot!r}")
        boot_device_id = created_boot["id"]
        if created_boot.get("attributes", {}).get("path") != paths["boot_zvol_path"]:
            raise V1ProbeError(
                f"boot DISK/ZVOL path mismatch: {created_boot.get('attributes', {}).get('path')!r}"
            )
        if not ddp_call(ws, "observe-boot-zvol", "pool.dataset.query", [[["id", "=", paths["boot_zvol"]]]]):
            raise V1ProbeError("owned boot ZVOL was not independently observable after device create")
        convert_job = ddp_call(ws, "convert-boot", "vm.device.convert", [{
            "source": paths["raw_image"],
            "destination": paths["boot_zvol_path"],
        }])
        wait_job(ws, convert_job, a.job_timeout, "convert-boot")
        ddp_call(ws, "seed-device", "vm.device.create", [seed])
        receipt["desired_devices"] = [boot, seed]
        receipt["media_lowering"] = {
            "source": paths["raw_image"],
            "destination": paths["boot_zvol_path"],
            "method": "vm.device.convert",
            "classification": "SUPPORTED",
        }

        ddp_call(ws, "vm-start", "vm.start", [vm_id, {"overcommit": False}])
        console = observe_console_nonce(
            a.host, a.port, password, vm_id, a.nonce, a.guest_timeout, a.tls,
        )
        receipt["guest_oracle"] = console
        if console.get("classification") != "SUPPORTED" or console.get("oracleSatisfied") is not True:
            raise V1ProbeError(f"guest nonce oracle failed: {console.get('detail')}")

        receipt.update({
            "classification": "SUPPORTED",
            "oracleSatisfied": True,
            "v1_oracle_satisfied": True,
            "detail": "pinned CirrOS guest booted and exact injected nonce was observed through supported TrueNAS VM console",
        })
        return receipt
    except Exception as exc:
        receipt["detail"] = f"{type(exc).__name__}: {exc}"
        return receipt
    finally:
        receipt["cleanup"]["attempted"] = True
        if ws is not None:
            if vm_id is not None:
                try:
                    ddp_call(ws, "cleanup-stop", "vm.stop", [vm_id, {"force": True, "force_after_timeout": True}])
                except Exception:
                    pass
                if boot_device_id is not None:
                    try:
                        boot_rows = ddp_call(
                            ws, "cleanup-query-boot-device", "vm.device.query", [[["id", "=", boot_device_id]]]
                        )
                        if boot_rows:
                            ddp_call(
                                ws,
                                "cleanup-delete-boot-device",
                                "vm.device.delete",
                                [boot_device_id, {"force": True, "zvol": True, "raw_file": False}],
                            )
                    except Exception:
                        pass
                try:
                    ddp_call(ws, "cleanup-delete-vm", "vm.delete", [vm_id, {"zvols": False, "force": True}])
                except Exception:
                    pass
                try:
                    receipt["cleanup"]["vm_absent"] = not bool(
                        ddp_call(ws, "cleanup-query-vm", "vm.query", [[["id", "=", vm_id]]])
                    )
                except Exception:
                    pass
            else:
                receipt["cleanup"]["vm_absent"] = True

            try:
                zvol_rows = ddp_call(
                    ws, "cleanup-query-boot-zvol", "pool.dataset.query", [[["id", "=", paths["boot_zvol"]]]]
                )
                if zvol_rows:
                    ddp_call(
                        ws,
                        "cleanup-delete-boot-zvol",
                        "pool.dataset.delete",
                        [paths["boot_zvol"], {"recursive": True, "force": True}],
                    )
                receipt["cleanup"]["boot_zvol_absent"] = not bool(
                    ddp_call(
                        ws,
                        "cleanup-confirm-boot-zvol",
                        "pool.dataset.query",
                        [[["id", "=", paths["boot_zvol"]]]],
                    )
                )
            except Exception:
                pass

            if stage_owned:
                try:
                    ddp_call(ws, "cleanup-stage", "pool.dataset.delete", [
                        paths["dataset"], {"recursive": True, "force": True}
                    ])
                except Exception:
                    pass
                try:
                    receipt["cleanup"]["staging_dataset_absent"] = not bool(
                        ddp_call(ws, "cleanup-query-stage", "pool.dataset.query", [[["id", "=", paths["dataset"]]]])
                    )
                except Exception:
                    pass
            else:
                receipt["cleanup"]["staging_dataset_absent"] = True
            ws.close()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--job-timeout", type=float, default=300)
    p.add_argument("--guest-timeout", type=float, default=120)
    p.add_argument("--username", default="truenas_admin")
    p.add_argument("--password-file", type=pathlib.Path)
    p.add_argument("--target-version", default="26.0.0-BETA.3")
    p.add_argument("--pool", default="rdtepool")
    p.add_argument("--name", default="rdtecomputevmv1")
    p.add_argument("--nonce", required=True)
    p.add_argument("--source-image", type=pathlib.Path)
    p.add_argument("--raw-image", type=pathlib.Path)
    p.add_argument("--seed-iso", type=pathlib.Path)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--apply", action="store_true")
    a = p.parse_args()

    try:
        if a.apply:
            if not all((a.port, a.password_file, a.source_image, a.raw_image, a.seed_iso)):
                raise V1ProbeError("apply requires port/password-file/source-image/raw-image/seed-iso")
            result = run_apply(a)
        else:
            result = plan(a.pool, a.name, a.nonce)
    except (V1ProbeError, SeedError, OSError) as exc:
        result = {
            "schema": "truenas-compute-vm-v1/v1",
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "v1_oracle_satisfied": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
