#!/usr/bin/env python3
"""Bounded public Alpine image-checksum manifest census, no VM or ISO download.

Fixed official Alpine release reference. Reports only publicly available SHA256
and source classification. A TLS-fetched checksum manifest is not a GPG
signature validation, and does not verify the image bytes.
"""
import hashlib
import json
import re
import sys
import urllib.request

VERSION = "3.24.2"
FILENAME = f"alpine-virt-{VERSION}-x86_64.iso"
EXPECTED_SHA256 = "3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b"
ISO_URL = f"https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/{FILENAME}"
MANIFEST_URL = (
    f"https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/{FILENAME}.sha256"
)


def parse_manifest(raw: bytes) -> str:
    if len(raw) > 512:
        raise ValueError("oversized public checksum manifest")
    try:
        content = raw.decode("ascii").strip()
    except UnicodeDecodeError as ex:
        raise ValueError("manifest is not ASCII") from ex
    match = re.fullmatch(r"([A-Fa-f0-9]{64})  \*?" + re.escape(FILENAME), content)
    if not match:
        raise ValueError("wrong digest format or target filename")
    return match.group(1).lower()


def read_public_checksum() -> dict:
    # No user-supplied URLs, credentials, redirects to new domains, or ISO bytes.
    class ExactAlpineRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("unexpected redirect in official checksum fetch")

    opener = urllib.request.build_opener(ExactAlpineRedirects())
    request = urllib.request.Request(
        MANIFEST_URL,
        headers={"User-Agent": "public-alpine-manifest-census/1.0"},
        method="GET",
    )
    with opener.open(request, timeout=15) as response:
        # Bytes read bounded to 513 regardless of advertised content length.
        raw = response.read(513)
    digest = parse_manifest(raw)
    if digest != EXPECTED_SHA256:
        raise ValueError("official SHA256 manifest differs from previously pinned digest")
    return {
        "evidence_class": "PUBLIC_CDN_SHA256_MANIFEST_READBACK",
        "asset": FILENAME,
        "manifest_url": MANIFEST_URL,
        "declared_sha256": digest,
        "actual_iso_downloaded": False,
        "actual_iso_hash_verified": False,
        "gpg_signature_verified": False,
        "guest_booted": False,
    }


def verify_iso_stream():
    """Hash public ISO bytes in memory only, enforce fixed size and pinned hash."""
    report = read_public_checksum()
    class ExactAlpineRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("unexpected redirect in official ISO fetch")
    opener = urllib.request.build_opener(ExactAlpineRedirects())
    request = urllib.request.Request(
        ISO_URL, headers={"User-Agent": "public-alpine-iso-hash-verifier/1.0"},
        method="GET")
    digest = hashlib.sha256()
    byte_count = 0
    limit = 128 * 1024 * 1024
    with opener.open(request, timeout=30) as response:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > limit:
                raise ValueError("ISO exceeded fixed public size bound")
            digest.update(chunk)
    if digest.hexdigest() != EXPECTED_SHA256:
        raise ValueError("actual ISO bytes do not match immutable pinned SHA256")
    report["evidence_class"] = "PUBLIC_ISO_BYTES_SHA256_MATCH"
    report["actual_iso_downloaded"] = True
    report["actual_iso_hash_verified"] = True
    report["streamed_bytes"] = byte_count
    return report


if __name__ == "__main__":
    if sys.argv[1:] == ["--fetch"]:
        report = read_public_checksum()
    elif sys.argv[1:] == ["--verify-iso"]:
        report = verify_iso_stream()
    else:
        raise SystemExit("usage: alpine_manifest.py --fetch|--verify-iso")
    print(json.dumps(report, sort_keys=True))
