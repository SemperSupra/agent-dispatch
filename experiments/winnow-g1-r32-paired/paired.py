#!/usr/bin/env python3
"""Public-safe, source-free R32 paired native URL-contract observation.

This script compares two upstream *native dispatch* APIs against the same
predeclared reference policy. It does NOT import private Winnow source,
exercise the production Go guard, download anything, or qualify no-login use.
Python socket instrumentation is not kernel egress confinement.
"""
import json
import platform
import re
import socket
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

CASES = [
    ("canonical_post", "https://www.instagram.com/p/FAKE001/", True),
    ("canonical_no_slash", "https://instagram.com/p/FAKE001", True),
    ("insecure_http", "http://www.instagram.com/p/FAKE001/", False),
    ("userinfo_credentials", "https://user:pass@www.instagram.com/p/FAKE001/", False),
    ("nondefault_port", "https://www.instagram.com:4443/p/FAKE001/", False),
    ("explicit_default_port", "https://www.instagram.com:443/p/FAKE001/", False),
    ("lookalike_host", "https://www.instagram.com.evil.invalid/p/FAKE001/", False),
    ("loopback_ip", "https://127.0.0.1/p/FAKE001/", False),
    ("file_scheme", "file:///etc/passwd", False),
    ("profile_not_post", "https://www.instagram.com/someprofile/", False),
    ("extra_path", "https://www.instagram.com/p/FAKE001/extra", False),
    ("embedded_query", "https://www.instagram.com/p/FAKE001/?x=1", False),
    ("fragment", "https://www.instagram.com/p/FAKE001/#fragment", False),
    ("encoded_path", "https://www.instagram.com/%70/FAKE001/", False),
]


def reference_policy(url):
    """Example strict policy, NOT an assertion about Winnow's actual Go code."""
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname in ("instagram.com", "www.instagram.com")
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
            and parsed.query == ""
            and parsed.fragment == ""
            and re.fullmatch(r"/p/[A-Za-z0-9_-]{5,}/?", parsed.path) is not None
        )
    except ValueError:
        return False


def record_native_gallery(extractor, url):
    selected = extractor.find(url)
    return bool(selected) and type(selected).__module__.startswith("gallery_dl.extractor.instagram")


def record_native_parth(validate_url, validation_error, url):
    try:
        return validate_url(url) is True
    except (validation_error, ValueError):
        return False


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: paired.py <result.json>")
    dest = Path(sys.argv[1])
    dest.parent.mkdir(parents=True, exist_ok=True)
    events = []

    def deny_socket(*_args, **_kwargs):
        events.append("blocked_python_socket_call")
        raise RuntimeError("R32_TEST_NETWORK_DENIED")

    # Interception is installed before importing either candidate, not merely
    # around the pure classifier functions. Native/C library and child-process
    # network behavior is OUTSIDE this Python instrumentation boundary.
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(socket.socket, "connect", side_effect=deny_socket))
        stack.enter_context(mock.patch.object(socket.socket, "connect_ex", side_effect=deny_socket))
        stack.enter_context(mock.patch.object(socket, "create_connection", side_effect=deny_socket))
        stack.enter_context(mock.patch.object(socket, "getaddrinfo", side_effect=deny_socket))

        # Explicit positive canary for the Python-level monitor: block before
        # any DNS lookup or outgoing connection can occur.
        canary_denied = False
        try:
            socket.create_connection(("example.invalid", 443), timeout=0.01)
        except RuntimeError as exc:
            canary_denied = str(exc) == "R32_TEST_NETWORK_DENIED"
        if not canary_denied or len(events) != 1:
            raise RuntimeError("R32_PYTHON_SOCKET_CANARY_FAILED")
        events.clear()

        import gallery_dl.extractor as extractor
        from parth_dl.utils import ValidationError, validate_url

        records = []
        for case_id, url, expected in CASES:
            if reference_policy(url) != expected:
                raise RuntimeError("R32_REFERENCE_POLICY_ORACLE_INVALID:" + case_id)
            results = {}
            for vendor in ("gallery-dl", "parth-dl"):
                try:
                    native = (
                        record_native_gallery(extractor, url) if vendor == "gallery-dl"
                        else record_native_parth(validate_url, ValidationError, url)
                    )
                except Exception as exc:
                    raise RuntimeError(
                        "R32_NATIVE_DISPATCH_SETUP_FAILED:%s:%s:%s" %
                        (vendor, case_id, type(exc).__name__)
                    ) from exc
                results[vendor] = {
                    "native_accept": bool(native),
                    "matches_reference_policy": bool(native) == expected,
                }
            records.append({
                "case": case_id,
                "reference_policy_accept": expected,
                "observations": results,
            })

    if events:
        raise RuntimeError("R32_PYTHON_NETWORK_ATTEMPTS_NOT_ZERO: %s" % len(events))
    if len(records) != len(CASES) or not all(
        row["observations"]["gallery-dl"]["native_accept"]
        and row["observations"]["parth-dl"]["native_accept"]
        for row in records if row["reference_policy_accept"]
    ):
        raise RuntimeError("R32_BASELINE_VALID_POST_NOT_RECOGNIZED")

    mismatches = {
        vendor: sum(not row["observations"][vendor]["matches_reference_policy"] for row in records)
        for vendor in ("gallery-dl", "parth-dl")
    }
    report = {
        "schema_version": 1,
        "qualification": "NATIVE_URL_DISPATCH_OBSERVATION_ONLY",
        "source": "PUBLIC_SYNTHETIC_LITERAL_CORPUS",
        "arch": platform.machine(),
        "python": platform.python_version(),
        "case_count": len(records),
        "candidate_count": 2,
        "python_socket_guard_canary_pass": canary_denied,
        "python_socket_attempts_during_classification": len(events),
        "os_kernel_egress_confinement_verified": False,
        "process_descendant_egress_verified": False,
        "no_login_instagram_access_verified": False,
        "original_image_bytes_verified": False,
        "selected_carousel_child_verified": False,
        "production_go_boundary_exercised": False,
        "reference_policy_mismatches": mismatches,
        "cases": records,
    }
    dest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        "R32_PAIRED_MATRIX_COMPLETE arch=%s cases=%d gallery_mismatch=%d parth_mismatch=%d "
        "python_socket_guard=PASS source=NOT_RUN" %
        (report["arch"], len(records), mismatches["gallery-dl"], mismatches["parth-dl"])
    )


if __name__ == "__main__":
    main()
