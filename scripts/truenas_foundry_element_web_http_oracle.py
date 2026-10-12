#!/usr/bin/env python3
"""Loopback HTTP semantic oracle for actual pinned Element Web container.

Never use a mock response or middleware RUNNING state as an app oracle. A PASS
is a narrow live-container semantic control, not TrueNAS F0-F5 or APPLY.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import sys
import time
from pathlib import Path


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def get(port: int, route: str) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4.0)
    try:
        conn.request("GET", route, headers={"Accept": "application/json"})
        response = conn.getresponse()
        data = response.read(65537)
        if len(data) > 65536:
            raise ValueError(f"{route} response too large")
        return response.status, data
    finally:
        conn.close()


def check(port: int, expected_version: str, expected_config: dict) -> dict:
    if not re.fullmatch(r"\d+\.\d+\.\d+", expected_version):
        raise ValueError("expected image version must be an exact numeric triplet")
    s, body = get(port, "/version")
    if s != 200:
        raise ValueError(f"/version HTTP status {s} is not 200")
    try:
        parsed = json.loads(body)
        version_text = json.dumps(parsed, sort_keys=True) if isinstance(parsed, (dict, list)) else str(parsed)
    except (ValueError, UnicodeError):
        version_text = body.decode("utf-8", errors="strict")
    regex = r"(?<![0-9])v?" + re.escape(expected_version) + r"(?![0-9])"
    if not re.search(regex, version_text) or len(body) > 4096:
        raise ValueError("/version did not prove exact pinned Element Web version")
    s, body = get(port, "/config.json")
    if s != 200:
        raise ValueError(f"/config.json HTTP status {s} is not 200")
    try:
        config = json.loads(body)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("/config.json is not valid JSON") from exc
    if not isinstance(config, dict) or config != expected_config:
        raise ValueError("/config.json does not equal owned persisted config")
    if not isinstance(config.get("brand"), str) or not config["brand"].startswith("4RDTE-"):
        raise ValueError("/config.json lacks owned 4RDTE sentinel")
    return {
        "schema": "truenas-foundry-element-web-http-oracle/v1",
        "classification": "APP_HTTP_SEMANTIC_SUPPORTED_NOT_TRUE_NAS",
        "version": expected_version,
        "config_sha256": "sha256:" + digest(config),
        "version_http": 200,
        "config_http": 200,
        "source_or_true_nas_f0_f5_qualified": False,
        "physical_apply_authority": "HOLD",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--expected-version", required=True)
    p.add_argument("--expected-config", type=Path, required=True)
    p.add_argument("--startup-timeout", type=float, default=90.0)
    args = p.parse_args()
    try:
        if not 1 <= args.port <= 65535:
            raise ValueError("invalid loopback port")
        expected = json.loads(args.expected_config.read_text(encoding="utf-8"))
        deadline = time.monotonic() + args.startup_timeout
        while True:
            try:
                result = check(args.port, args.expected_version, expected)
                break
            except (ConnectionError, OSError, TimeoutError) as exc:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Element Web did not accept loopback HTTP") from exc
                time.sleep(2)
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        print(json.dumps({
            "schema": "truenas-foundry-element-web-http-oracle/v1",
            "classification": "ORACLE_FAILURE",
            "error_type": type(exc).__name__,
            "source_or_true_nas_f0_f5_qualified": False,
            "physical_apply_authority": "HOLD",
        }, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
