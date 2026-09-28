#!/usr/bin/env python3
"""Bounded TrueNAS middleware client for the T3 disposable ZFS-pool oracle."""
from __future__ import annotations

import argparse
import json
import pathlib
import time

from truenas_middleware_ddp_probe import WebSocket, ddp_call, wait_for


def disk_name(disk):
    return disk.get("devname") or disk.get("name")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--pool-name", default="rdtepool")
    p.add_argument("--expected-data-disks", type=int, default=2)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--job-timeout", type=float, default=180.0)
    a = p.parse_args()

    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
    payload = {
        "schema": "truenas-middleware-pool-t3/v1",
        "oracleSatisfied": False,
        "classification": "ORACLE_FAILURE",
        "pool_name": a.pool_name,
        "expected_data_disks": a.expected_data_disks,
        "transport": "wss" if a.tls else "ws",
    }
    started = time.time()
    ws = None
    try:
        ws = WebSocket(a.host, a.port, timeout=a.timeout, tls=a.tls)
        ws.send_json({"msg": "connect", "version": "1", "support": ["1"]})
        connected = wait_for(ws, lambda m: m.get("msg") in {"connected", "failed"})
        if connected.get("msg") != "connected":
            raise RuntimeError(f"DDP connection failed: {connected!r}")

        auth = ddp_call(
            ws, "1", "auth.login_ex",
            [{
                "mechanism": "PASSWORD_PLAIN",
                "username": "truenas_admin",
                "password": password,
            }],
        )
        payload["auth_response_type"] = auth.get("response_type") if isinstance(auth, dict) else None
        if payload["auth_response_type"] != "SUCCESS":
            raise RuntimeError(f"authentication did not return SUCCESS: {auth!r}")

        payload["system_version"] = ddp_call(ws, "2", "system.version", [])
        boot_disks = ddp_call(ws, "3", "boot.get_disks", [])
        payload["boot_disks"] = sorted(boot_disks)
        unused = ddp_call(ws, "4", "disk.get_unused", [])
        payload["unused_disks"] = unused

        if len(unused) != a.expected_data_disks:
            raise RuntimeError(
                f"refusing pool mutation: expected exactly {a.expected_data_disks} unused data disks, found {len(unused)}"
            )
        selected = [disk_name(disk) for disk in unused]
        if any(not name for name in selected):
            raise RuntimeError("refusing pool mutation: unused disk missing name/devname")
        if len(set(selected)) != len(selected):
            raise RuntimeError("refusing pool mutation: duplicate data-disk names")
        if set(selected) & set(boot_disks):
            raise RuntimeError("refusing pool mutation: a selected data disk overlaps the boot pool")
        payload["selected_data_disks"] = sorted(selected)

        existing = ddp_call(ws, "5", "pool.query", [[["name", "=", a.pool_name]]])
        if existing:
            raise RuntimeError(f"refusing pool mutation: pool {a.pool_name!r} already exists")

        create = {
            "name": a.pool_name,
            "encryption": False,
            "allow_duplicate_serials": True,
            "topology": {
                "data": [{
                    "type": "MIRROR",
                    "disks": selected,
                }],
            },
        }
        payload["create_contract"] = {
            "name": a.pool_name,
            "encryption": False,
            "allow_duplicate_serials": True,
            "topology": {"data": [{"type": "MIRROR", "disks": sorted(selected)}]},
        }
        job_id = ddp_call(ws, "6", "pool.create", [create])
        if not isinstance(job_id, int):
            raise RuntimeError(f"pool.create did not return a legacy DDP job id: {job_id!r}")
        payload["job_id"] = job_id

        deadline = time.monotonic() + a.job_timeout
        job = None
        poll = 7
        while time.monotonic() < deadline:
            result = ddp_call(
                ws, str(poll), "core.get_jobs",
                [[["id", "=", job_id]], {"get": True}],
            )
            poll += 1
            if result:
                job = result
                state = job.get("state")
                payload["job_state"] = state
                payload["job_progress"] = job.get("progress")
                if state == "SUCCESS":
                    break
                if state in {"FAILED", "ABORTED"}:
                    raise RuntimeError(
                        f"pool.create job {state}: {job.get('error') or job.get('exception')}"
                    )
            time.sleep(1)
        else:
            raise RuntimeError("pool.create job did not reach a terminal state within the bounded timeout")

        if not job or job.get("state") != "SUCCESS":
            raise RuntimeError(f"pool.create did not reach SUCCESS: {job!r}")

        pool = ddp_call(
            ws, str(poll), "pool.query",
            [[["name", "=", a.pool_name]], {"get": True}],
        )
        poll += 1
        payload["pool"] = pool
        if pool.get("name") != a.pool_name:
            raise RuntimeError(f"pool query returned wrong name: {pool.get('name')!r}")
        if pool.get("status") != "ONLINE":
            raise RuntimeError(f"created pool is not ONLINE: {pool.get('status')!r}")
        if pool.get("healthy") is not True:
            raise RuntimeError(f"created pool is not healthy: {pool.get('healthy')!r}")

        pool_disks = ddp_call(ws, str(poll), "pool.get_disks", [pool["id"]])
        payload["pool_disks"] = sorted(pool_disks)
        if set(pool_disks) != set(selected):
            raise RuntimeError(
                f"pool disk membership mismatch: selected={sorted(selected)!r} pool={sorted(pool_disks)!r}"
            )

        payload["oracleSatisfied"] = True
        payload["classification"] = "SUPPORTED"
        payload["detail"] = "real two-disk mirror pool is ONLINE, healthy, and owns exactly the selected disposable disks"
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
