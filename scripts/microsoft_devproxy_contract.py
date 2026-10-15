#!/usr/bin/env python3
"""Microsoft Dev Proxy fixture-only contract. NEVER use a real API URL or token."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from email.parser import Parser

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "microsoft"
ORIGIN = "http://graph-fixture.invalid"
STEM = ORIGIN + "/v1.0/approot/"
EXPECTED = {
    "ok": (200, "MOCK_OK"),
    "unauthorized": (401, "AUTH_REQUIRED"),
    "provisioning": (403, "PROVIDER_PROVISIONING_CANDIDATE"),
    "missing": (404, "ITEM_NOT_FOUND"),
    "expired": (410, "CURSOR_EXPIRED"),
    "conflict": (412, "REVISION_CONFLICT"),
    "throttle": (429, "RETRY_BOUNDED"),
    "unavailable": (503, "TRANSIENT_FAILURE"),
}
IMAGE = "ghcr.io/dotnet/dev-proxy@sha256:18b2ac21a29bc60c3bbbe7a0e00fa3fed2179b492632ca5d5aad6ed60bd8e875"
IMAGE_VERSION = "3.3.1"


class Denied(ValueError):
    pass


def _object_pairs(pairs):
    o = {}
    for key, value in pairs:
        if key in o:
            raise Denied("DUPLICATE_JSON_FIELD")
        o[key] = value
    return o


def _read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
        raise Denied("UNSAFE_FIXTURE")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object_pairs)


def validate_fixtures():
    config = _read_json(FIXTURES / "devproxyrc.json")
    mocks = _read_json(FIXTURES / "mocks.json")
    allowed_config = {"$schema", "plugins", "urlsToWatch", "mockResponsePlugin",
                      "logLevel", "showSkipMessages"}
    if set(config) != allowed_config or config["urlsToWatch"] != [ORIGIN + "/*"]:
        raise Denied("UNEXPECTED_WATCH_TARGET")
    p = config["plugins"]
    if not isinstance(p, list) or len(p) != 1 or p[0] != {
        "name": "MockResponsePlugin", "enabled": True,
        "pluginPath": "~appFolder/plugins/DevProxy.Plugins.dll",
        "configSection": "mockResponsePlugin"
    }:
        raise Denied("UNEXPECTED_PLUGIN")
    if config["mockResponsePlugin"] != {
        "mocksFile": "mocks.json", "blockUnmockedRequests": True
    }:
        raise Denied("UNMOCKED_PASS_THROUGH")
    if set(mocks) != {"mocks"} or not isinstance(mocks["mocks"], list):
        raise Denied("UNEXPECTED_MOCK_FIELDS")
    cases = {}
    for m in mocks["mocks"]:
        if set(m) != {"request", "response"}:
            raise Denied("UNEXPECTED_MOCK_FIELDS")
        req, resp = m["request"], m["response"]
        if set(req) != {"url", "method"} or req["method"] != "GET":
            raise Denied("UNEXPECTED_METHOD")
        if not isinstance(req["url"], str) or not req["url"].startswith(STEM):
            raise Denied("UNEXPECTED_MOCK_URL")
        case = req["url"][len(STEM):]
        if case not in EXPECTED or case in cases:
            raise Denied("UNEXPECTED_CASE")
        if set(resp) != {"statusCode", "body", "headers"}:
            raise Denied("UNEXPECTED_RESPONSE")
        if type(resp["statusCode"]) is not int or resp["statusCode"] != EXPECTED[case][0]:
            raise Denied("UNEXPECTED_STATUS")
        if not isinstance(resp["body"], dict) or not isinstance(resp["headers"], list):
            raise Denied("UNEXPECTED_BODY")
        for h in resp["headers"]:
            if set(h) != {"name", "value"} or h["name"].lower() not in {
                "content-type", "retry-after"
            }:
                raise Denied("UNEXPECTED_HEADER")
        cases[case] = resp
    if set(cases) != set(EXPECTED):
        raise Denied("INCOMPLETE_CASES")
    if cases["provisioning"]["body"].get("error", {}).get("innerError", {}).get("code") != "serviceReadOnly":
        raise Denied("PROVISIONING_ORACLE_MISSING")
    if not any(h["name"].lower() == "retry-after" and h["value"] == "2"
               for h in cases["throttle"]["headers"]):
        raise Denied("THROTTLE_ORACLE_MISSING")
    return hashlib.sha256((FIXTURES / "devproxyrc.json").read_bytes() +
                          (FIXTURES / "mocks.json").read_bytes()).hexdigest()


def classify(status, body, headers):
    if type(status) is not int or not isinstance(body, dict):
        raise Denied("MALFORMED_RESPONSE")
    code = body.get("error", {}).get("code") if isinstance(body.get("error"), dict) else None
    if status == 200 and isinstance(body.get("item"), dict):
        return "MOCK_OK"
    if status == 401:
        return "AUTH_REQUIRED"
    if (status == 403 and code == "accessDenied" and
            body["error"].get("innerError", {}).get("code") == "serviceReadOnly"):
        # Without real consent evidence this is NEVER a confirmed provisioning failure.
        return "PROVIDER_PROVISIONING_CANDIDATE"
    if status == 404 and code == "itemNotFound":
        return "ITEM_NOT_FOUND"
    if status == 410 and code == "resyncRequired":
        return "CURSOR_EXPIRED"
    if status == 412 and code == "preconditionFailed":
        return "REVISION_CONFLICT"
    if status == 429:
        wait = headers.get("Retry-After")
        if not isinstance(wait, str) or not re.fullmatch(r"[0-9]{1,2}", wait):
            return "RETRY_DENIED"
        return "RETRY_BOUNDED" if int(wait) <= 5 else "RETRY_DENIED"
    if status == 503:
        return "TRANSIENT_FAILURE"
    raise Denied("UNRECOGNIZED_RESPONSE")


def _request_from_isolated_container(name: str, container: str):
    if not re.fullmatch(r"msmock-[0-9]{1,20}-[0-9]{1,4}-proxy", container):
        raise Denied("UNAPPROVED_CONTAINER")
    if not re.fullmatch(r"[a-z]{2,25}", name):
        raise Denied("UNAPPROVED_CASE")
    command = ["docker", "exec", container, "curl", "--silent", "--show-error",
               "--max-time", "5", "--proxy", "http://127.0.0.1:8000",
               "--dump-header", "-", "--write-out", "\n%{http_code}", STEM + name]
    try:
        result = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=9)
    except subprocess.TimeoutExpired as exc:
        raise Denied("FIXTURE_REQUEST_TIMEOUT") from exc
    if result.returncode != 0:
        raise Denied("FIXTURE_TRANSPORT_FAILED")
    try:
        http_part, status_raw = result.stdout.rsplit(b"\n", 1)
        head, data = http_part.split(b"\r\n\r\n", 1)
        status = int(status_raw.decode("ascii"))
        headers = Parser().parsestr(head.decode("ascii", "strict").split("\r\n", 1)[1])
    except (ValueError, UnicodeDecodeError, IndexError) as exc:
        raise Denied("FIXTURE_HTTP_MALFORMED") from exc
    return status, data, headers


def probe(container):
    if not re.fullmatch(r"msmock-[0-9]{1,20}-[0-9]{1,4}-proxy", container):
        raise Denied("UNAPPROVED_CONTAINER")
    digest = validate_fixtures()
    cases = {}
    for name, (expected_status, expected_class) in EXPECTED.items():
        status, data, headers = _request_from_isolated_container(name, container)
        if status != expected_status:
            raise Denied("PROXY_STATUS_MISMATCH")
        try:
            body = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as ex:
            raise Denied("PROXY_JSON_MALFORMED") from ex
        actual = classify(status, body, headers)
        if actual != expected_class:
            raise Denied("PROXY_CLASS_MISMATCH")
        cases[name] = actual
    unmocked, _unmocked_data, _unmocked_headers = _request_from_isolated_container("unmocked", container)
    if unmocked != 502:
        raise Denied("UNMOCKED_REQUEST_NOT_BLOCKED")
    source = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch("[0-9a-f]{40}", source):
        raise Denied("SOURCE_SHA_REQUIRED")
    if os.environ.get("RUNNER_ARCH", "") != "X64":
        raise Denied("RUNNER_SHAPE_DENIED")
    return {
        "schema": "microsoft-mock-contract-receipt/v1",
        "data_class": "public-synthetic",
        "source_sha": source,
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "fixture_sha256": digest,
        "image": IMAGE,
        "image_version": IMAGE_VERSION,
        "expected_cases": len(EXPECTED),
        "passed_cases": len(cases),
        "cases": cases,
        "unmocked_status": unmocked,
        "provider_access_verified": False,
        "identity_verified": False,
        "max_cost_usd": 0,
        "classification": "MOCK_ONLY_PASS",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", required=True, choices=["validate", "probe"])
    parser.add_argument("--container", default="")
    parser.add_argument("--receipt")
    args = parser.parse_args()
    try:
        if args.action == "validate":
            print("FIXTURE_CONTRACT_VALID " + validate_fixtures())
        else:
            if not args.receipt:
                raise Denied("RECEIPT_PATH_REQUIRED")
            data = probe(args.container)
            out = Path(args.receipt)
            if out.exists() or out.is_symlink():
                raise Denied("RECEIPT_ALREADY_EXISTS")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")
            print("MICROSOFT_MOCK_ONLY_PASS")
    except (Denied, OSError, ValueError) as ex:
        print("MICROSOFT_MOCK_BLOCKED " + type(ex).__name__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
