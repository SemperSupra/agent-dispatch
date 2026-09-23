#!/usr/bin/env python3
"""Discover one exact official Firecracker CI guest-kernel candidate for F1.

This is discovery only. It does not boot a guest. The output is intended to be
reviewed and pinned by key + SHA-256 before any F1 boot attempt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import platform
import re
import shutil
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

S3_BASE = "https://s3.amazonaws.com/spec.ccfc.min"
SCHEMA = "firecracker-f1-kernel-discovery/v1"
PREFIX_RE = re.compile(r"^firecracker-ci/[0-9]{8}-[^/]+/$")
KERNEL_RE = re.compile(r"/vmlinux-([0-9]+)\.([0-9]+)\.([0-9]+)$")


def _get(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "SemperSupra-agent-dispatch-firecracker-f1-discovery/1"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _list_url(*, prefix: str, delimiter: str | None = None) -> str:
    params = {"list-type": "2", "prefix": prefix}
    if delimiter is not None:
        params["delimiter"] = delimiter
    return S3_BASE + "?" + urllib.parse.urlencode(params)


def _parse_common_prefixes(payload: bytes) -> list[str]:
    root = ET.fromstring(payload)
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    return [el.text or "" for el in root.findall("s3:CommonPrefixes/s3:Prefix", ns)]


def _parse_keys(payload: bytes) -> list[str]:
    root = ET.fromstring(payload)
    ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    return [el.text or "" for el in root.findall("s3:Contents/s3:Key", ns)]


def _select_latest_ci_prefix(prefixes: list[str]) -> str:
    candidates = [p for p in prefixes if PREFIX_RE.match(p)]
    if not candidates:
        raise ValueError("no Firecracker CI build prefixes found")
    return sorted(candidates)[-1]


def _kernel_version(key: str) -> tuple[int, int, int]:
    match = KERNEL_RE.search(key)
    if not match:
        raise ValueError(f"not a recognized guest-kernel key: {key}")
    return tuple(int(part) for part in match.groups())


def _select_latest_kernel(keys: list[str], ci_prefix: str, arch: str) -> str:
    required_prefix = f"{ci_prefix}{arch}/vmlinux-"
    candidates = [
        key for key in keys
        if key.startswith(required_prefix) and KERNEL_RE.search(key)
    ]
    if not candidates:
        raise ValueError("no matching guest-kernel artifacts found")
    return max(candidates, key=_kernel_version)


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def discover(out_path: pathlib.Path) -> dict:
    system = platform.system()
    arch = platform.machine()
    if system != "Linux" or arch not in {"x86_64", "amd64"}:
        return {
            "schema": SCHEMA,
            "authority": "SemperSupra/agent-dispatch-private#280",
            "classification": "SETUP_REQUIRED",
            "reason": "kernel discovery rep currently targets Linux x86_64",
            "guest_boot_claimed": False,
        }

    top_url = _list_url(prefix="firecracker-ci/", delimiter="/")
    prefixes = _parse_common_prefixes(_get(top_url))
    ci_prefix = _select_latest_ci_prefix(prefixes)

    kernel_list_url = _list_url(prefix=f"{ci_prefix}x86_64/vmlinux-")
    keys = _parse_keys(_get(kernel_list_url))
    kernel_key = _select_latest_kernel(keys, ci_prefix, "x86_64")
    kernel_url = f"{S3_BASE}/{kernel_key}"

    kernel_path = out_path.parent / pathlib.Path(kernel_key).name
    request = urllib.request.Request(
        kernel_url,
        headers={"User-Agent": "SemperSupra-agent-dispatch-firecracker-f1-discovery/1"},
    )
    with urllib.request.urlopen(request, timeout=120) as response, kernel_path.open("wb") as out:
        shutil.copyfileobj(response, out)

    digest = _sha256(kernel_path)
    size = kernel_path.stat().st_size

    return {
        "schema": SCHEMA,
        "authority": "SemperSupra/agent-dispatch-private#280",
        "classification": "SUPPORTED",
        "reason": "exact official Firecracker CI kernel candidate discovered and hashed",
        "guest_boot_claimed": False,
        "candidate": {
            "source": "official-firecracker-ci",
            "ci_prefix": ci_prefix,
            "architecture": "x86_64",
            "kernel_key": kernel_key,
            "kernel_version": ".".join(str(x) for x in _kernel_version(kernel_key)),
            "kernel_url": kernel_url,
            "sha256": digest,
            "size_bytes": size,
        },
        "discovery": {
            "top_index_url": top_url,
            "kernel_index_url": kernel_list_url,
            "selection_rule": "lexicographically latest YYYYMMDD CI prefix, then highest semantic vmlinux version",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = discover(args.out)
    except Exception as exc:
        receipt = {
            "schema": SCHEMA,
            "authority": "SemperSupra/agent-dispatch-private#280",
            "classification": "ENVIRONMENT_FAILURE",
            "reason": f"{type(exc).__name__}: {exc}",
            "guest_boot_claimed": False,
        }
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["classification"] == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
