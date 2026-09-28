#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import urllib.error
import urllib.request

BUILDER_RELEASES = {
    "dragonflybsd": "v0.0.2",
    "freebsd": "v0.17.0",
    "haiku": "v0.2.0",
    "netbsd": "v1.1.0",
    "openbsd": "v0.14.0",
    "omnios": "v0.2.0",
}


def intval(v):
    try:
        return int(v) if v else None
    except (TypeError, ValueError):
        return None


def parse(path):
    values = {}
    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v
    return values


def capability(name, ok, reason, evidence=None, negative="ORACLE_FAILURE"):
    return {
        "name": name,
        "advertised": None,
        "observed": ok,
        "installed": None,
        "callable": ok,
        "exercised": True,
        "oracleSatisfied": ok,
        "classification": "SUPPORTED" if ok else negative,
        "reason": reason,
        "evidence": evidence,
    }


def select_release_asset(release, os_name, version, arch):
    prefix = f"{os_name}-{version}-{arch}."
    matches = [
        asset for asset in release.get("assets", [])
        if str(asset.get("name", "")).startswith(prefix)
    ]
    return matches[0] if len(matches) == 1 else None


def resolve_guest_asset(os_name, version, arch):
    tag = BUILDER_RELEASES.get(os_name)
    if not tag:
        return {
            "classification": "INCONCLUSIVE",
            "reason": "no builder release mapping for pinned guest adapter",
            "repository": f"cross-platform-actions/{os_name}-builder",
            "release_tag": None,
        }

    repo = f"cross-platform-actions/{os_name}-builder"
    url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "SemperSupra-runner-census-v2",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            release = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {
            "classification": "INCONCLUSIVE",
            "reason": "public GitHub release metadata could not be resolved",
            "repository": repo,
            "release_tag": tag,
            "error_type": type(exc).__name__,
        }

    asset = select_release_asset(release, os_name, version, arch)
    if asset is None:
        return {
            "classification": "INCONCLUSIVE",
            "reason": "exact guest image asset was not uniquely resolved",
            "repository": repo,
            "release_tag": tag,
            "release_immutable": release.get("immutable"),
        }

    digest = asset.get("digest")
    immutable = release.get("immutable") is True
    oracle = immutable and isinstance(digest, str) and digest.startswith("sha256:")
    return {
        "classification": "SUPPORTED" if oracle else "INCONCLUSIVE",
        "reason": (
            "exact guest image is bound to an immutable release asset SHA-256"
            if oracle
            else "guest image asset resolved but immutable SHA-256 identity is incomplete"
        ),
        "repository": repo,
        "release_tag": tag,
        "release_immutable": release.get("immutable"),
        "asset_name": asset.get("name"),
        "asset_digest": digest,
        "asset_size_bytes": asset.get("size"),
        "asset_updated_at": asset.get("updated_at"),
        "asset_url": asset.get("browser_download_url"),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--raw", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--os", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--arch", required=True)
    p.add_argument("--parent-label", default="ubuntu-24.04")
    p.add_argument("--adapter-commit", required=True)
    a = p.parse_args()

    v = parse(a.raw)
    commands = {
        k[4:].replace("_", "-"): x == "1"
        for k, x in v.items()
        if k.startswith("CMD_")
    }
    cpu = intval(v.get("CPU_ONLINE"))
    mem = intval(v.get("MEM_BYTES"))
    total = intval(v.get("ROOT_TOTAL_KIB")) or 0
    free = intval(v.get("ROOT_FREE_KIB")) or 0
    identity = bool(v.get("UNAME_S") and v.get("UNAME_M"))
    guest_asset = resolve_guest_asset(a.os, a.version, a.arch)
    image_identity_ok = guest_asset.get("classification") == "SUPPORTED"

    symlink_ok = v.get("FS_SYMLINK") == "1"
    hardlink_ok = v.get("FS_HARDLINK") == "1"

    receipt = {
        "schema": "github-runner-capability/v1",
        "provenance": {
            "requested_label": f"qemu-guest:{a.os}:{a.version}:{a.arch}",
            "repository_visibility": os.environ.get("CENSUS_REPOSITORY_VISIBILITY", "public"),
            "workflow_sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "probe_version": "public-qemu-guest/2",
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "image_os": a.os,
            "image_version": a.version,
            "guest_adapter": {
                "repository": "cross-platform-actions/action",
                "commit": a.adapter_commit,
            },
            "guest_image": guest_asset,
        },
        "runner": {
            "system": v.get("UNAME_S", ""),
            "release": v.get("UNAME_R", ""),
            "machine": v.get("UNAME_M", ""),
            "architecture": a.arch,
            "runner_os": v.get("UNAME_S"),
            "runner_arch": v.get("UNAME_M"),
            "privileged": v.get("UID") == "0",
        },
        "resources": {
            "cpu": {"logical_processors": cpu, "model": None},
            "memory": {"total_bytes": mem, "available_bytes": None},
            "storage": [{
                "mount": "/",
                "filesystem": v.get("ROOT_FS"),
                "total_bytes": total * 1024,
                "free_bytes": free * 1024,
            }],
        },
        "environment": {
            "github_actions": True,
            "execution_model": "qemu-guest",
            "parent_runner_label": a.parent_label,
            "requested_guest_os": a.os,
            "requested_guest_version": a.version,
            "requested_guest_arch": a.arch,
            "adapter_repository": "cross-platform-actions/action",
            "adapter_commit": a.adapter_commit,
            "commands": commands,
            "uid": intval(v.get("UID")),
            "gid": intval(v.get("GID")),
            "case_insensitive": v.get("FS_CASE_INSENSITIVE") == "1",
        },
        "capabilities": [
            capability(
                "guest:identity",
                identity,
                "guest uname identity observed" if identity else "guest uname identity missing",
                {"uname_s": v.get("UNAME_S"), "uname_r": v.get("UNAME_R"), "uname_m": v.get("UNAME_M")},
            ),
            {
                "name": "guest:image-identity",
                "advertised": None,
                "observed": guest_asset.get("asset_name") is not None,
                "installed": None,
                "callable": image_identity_ok,
                "exercised": True,
                "oracleSatisfied": image_identity_ok,
                "classification": guest_asset.get("classification", "INCONCLUSIVE"),
                "reason": guest_asset.get("reason", "guest image identity unresolved"),
                "evidence": guest_asset,
            },
            capability(
                "filesystem:symlink",
                symlink_ok,
                "guest temp symlink read oracle" if symlink_ok else "guest temp filesystem did not support the symlink oracle",
                negative="NEGATIVE_OBSERVATION",
            ),
            capability(
                "filesystem:hardlink",
                hardlink_ok,
                "guest temp hardlink read oracle" if hardlink_ok else "guest temp filesystem did not support the hard-link oracle",
                negative="NEGATIVE_OBSERVATION",
            ),
        ],
        "observations": [{
            "name": "guest:command-surface",
            "value": commands,
            "unit": None,
            "note": "presence only; no package installation",
        }],
        "warnings": [
            "VM/QEMU guest portability evidence; not a native GitHub runner label",
            "parent GitHub-hosted runner is distinct",
            "third-party adapter is pinned to an exact commit",
            "guest image identity is accepted only when exact immutable release asset SHA-256 is resolved",
            "unsupported filesystem semantics are negative observations, not harness failures",
            "no package installation or stress workload performed",
        ],
    }

    path = pathlib.Path(a.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"GUEST_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
