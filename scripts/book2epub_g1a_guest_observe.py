#!/usr/bin/env python3
"""Bounded, read-only TrueNAS guest transport observation (NOT an image-pull oracle).

Designed for a separate, preauthorized, disposable Agent Dispatch guest capsule.
It cannot admit, dispatch or validate a production release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

VERSION = "25.04.2.6"
GATEWAY = "http://10.0.2.2:5000/v2/"
SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{7,95}\Z")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def read_command(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=10,
                           check=False, env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "failure": type(exc).__name__}
    out = p.stdout.strip()
    if p.returncode or not out or len(out) > 8192:
        return {"ok": False, "failure": "exit_nonzero_or_unbounded_output"}
    return {"ok": True, "text": out}


def read_gateway(url=GATEWAY):
    if url != GATEWAY:
        raise ValueError("only the pinned disposable guest-to-host gateway is allowed")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(Request(url, headers={"Accept": "application/json"}), timeout=4) as response:
            status = response.status
    except HTTPError as exc:
        status = exc.code
    except (URLError, OSError, TimeoutError):
        return {"reachable": False, "http_status": None, "auth_required": False}
    return {"reachable": status in (200, 401), "http_status": status,
            "auth_required": status == 401}


def observe(session_id, run_command=read_command, get_gateway=read_gateway):
    if not SESSION.fullmatch(session_id):
        raise ValueError("invalid bounded disposable session identity")
    verdict = {
        "schema": "book2epub-truenas-g1a-guest-readonly/v1",
        "session_id": session_id,
        "expected_target": VERSION,
        "method": "read-only guest-local midclt/docker CLI and pinned /v2/ GET",
        "registry_url": GATEWAY,
        "registry_transport": "EPHEMERAL_PLAINTEXT_DIAGNOSTIC_ONLY",
        "image_pull_performed": False,
        "engine_registry_trust_proven": False,
        "exact_digest_pull_proven": False,
        "book2epub_product_tested": False,
        "physical_truenas_apply": "HOLD",
        "classification": "BLOCKED_OBSERVATION",
        "observations": {},
    }
    version = run_command(["midclt", "call", "system.version"])
    if not version.get("ok"):
        verdict["observations"]["version_failure"] = version.get("failure", "unknown")
        return verdict
    # Both a plain version string and the JSON-string form are seen in CLI clients.
    reported = version["text"].strip('"')
    verdict["observations"]["version_match"] = bool(re.fullmatch(
        r"(?:TrueNAS-SCALE-)?25\.04\.2\.6(?:\+[^\s]+)?", reported))
    verdict["observations"]["version_stdout_sha256"] = hashlib.sha256(
        version["text"].encode()).hexdigest()
    if not verdict["observations"]["version_match"]:
        return verdict
    for name, argv in (
        ("server", ["docker", "version", "--format", "{{json .Server}}"]),
        ("registry", ["docker", "info", "--format", "{{json .RegistryConfig}}"]),
    ):
        outcome = run_command(argv)
        if not outcome.get("ok"):
            verdict["observations"][name + "_failure"] = outcome.get("failure", "unknown")
            return verdict
        try:
            document = json.loads(outcome["text"])
        except (json.JSONDecodeError, TypeError):
            verdict["observations"][name + "_failure"] = "non_json_docker_output"
            return verdict
        if not isinstance(document, dict) or not document:
            verdict["observations"][name + "_failure"] = "empty_docker_object"
            return verdict
        verdict["observations"][name + "_stdout_sha256"] = hashlib.sha256(
            outcome["text"].encode()).hexdigest()
        if name == "server":
            verdict["observations"]["docker_server_version_detected"] = bool(document.get("Version"))
        else:
            verdict["observations"]["docker_registry_config_detected"] = True
            verdict["observations"]["insecure_cidr_count"] = len(document.get("InsecureRegistryCIDRs") or [])
    if not verdict["observations"].get("docker_server_version_detected"):
        return verdict
    reach = get_gateway()
    verdict["observations"]["gateway"] = {
        "reachable": reach.get("reachable") is True,
        "http_status": reach.get("http_status"),
        "auth_required": reach.get("auth_required") is True,
    }
    if reach.get("reachable") is True:
        verdict["classification"] = "OBSERVED_NETWORK_ONLY_G1B_UNVERIFIED"
    return verdict


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--ack-disposable-guest", action="store_true", required=True)
    args = parser.parse_args(argv)
    if not args.ack_disposable_guest:
        parser.error("explicit disposable-guest acknowledgment is mandatory")
    try:
        receipt = observe(args.session_id)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0 if receipt["classification"] == "OBSERVED_NETWORK_ONLY_G1B_UNVERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
