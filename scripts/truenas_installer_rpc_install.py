#!/usr/bin/env python3
"""Bounded mutating client for the TrueNAS installer JSON-RPC API."""
from __future__ import annotations

import argparse
import json
import pathlib
import time

from truenas_installer_rpc_probe import WebSocket


def rpc_call(ws, method, request_id, params=None, progress=None):
    request = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        request["params"] = params
    ws.send_json(request)
    while True:
        message = json.loads(ws.recv_text())
        if message.get("method") == "installation_progress":
            values = message.get("params") or []
            if progress is not None and values and isinstance(values[0], dict):
                progress.append(values[0])
            continue
        if message.get("id") != request_id:
            continue
        if message.get("error") is not None:
            raise RuntimeError(f"{method}: {json.dumps(message['error'], sort_keys=True)}")
        return message.get("result")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=float, default=15.0)
    a = p.parse_args()

    password = pathlib.Path(a.password_file).read_text(encoding="utf-8").strip()
    if len(password) < 12:
        raise SystemExit("ephemeral install password must be at least 12 characters")

    payload = {
        "schema": "truenas-installer-rpc-install/v1",
        "oracleSatisfied": False,
        "classification": "ORACLE_FAILURE",
        "selected_disk": None,
        "selected_interface": None,
        "progress": [],
    }
    started = time.time()
    ws = None
    try:
        ws = WebSocket(a.host, a.port, timeout=a.timeout)
        adopted = rpc_call(ws, "is_adopted", 1)
        payload["is_adopted"] = adopted
        if adopted:
            raise RuntimeError("fresh disposable installer unexpectedly reports adopted=true")

        disks = rpc_call(ws, "list_disks", 2)
        payload["discovered_disks"] = disks
        candidates = [disk for disk in disks if not disk.get("removable", False)]
        if len(candidates) != 1:
            raise RuntimeError(
                f"refusing install: expected exactly one non-removable disk, found {len(candidates)}"
            )
        disk = candidates[0]
        payload["selected_disk"] = disk["name"]

        interfaces = rpc_call(ws, "list_network_interfaces", 3)
        payload["discovered_interfaces"] = interfaces
        if len(interfaces) != 1:
            raise RuntimeError(
                f"refusing install: expected exactly one non-loopback interface, found {len(interfaces)}"
            )
        interface = interfaces[0]
        payload["selected_interface"] = interface["name"]

        install_params = {
            "disks": [disk["name"]],
            "set_pmbr": True,
            "authentication": {
                "username": "truenas_admin",
                "password": password,
            },
            "post_install": {
                "network_interfaces": [
                    {
                        "name": interface["name"],
                        "ipv4_dhcp": True,
                        "ipv6_auto": True,
                    }
                ]
            },
        }
        rpc_call(ws, "install", 4, install_params, progress=payload["progress"])
        payload["oracleSatisfied"] = True
        payload["classification"] = "SUPPORTED"
        payload["detail"] = "vendor installer completed on the sole disposable disk"
        payload["install_contract"] = {
            "disk_count": 1,
            "set_pmbr": True,
            "authentication_username": "truenas_admin",
            "password_configured": True,
            "ipv4_dhcp": True,
            "ipv6_auto": True,
        }
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
