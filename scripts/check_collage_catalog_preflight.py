#!/usr/bin/env python3
"""Cheap read-only pre-KVM guard for rotating official TrueNAS Minecraft catalog.

Do not confuse this remote branch preflight with in-guest native catalog proof.
The official TrueNAS Apps catalog is independently updated and may retire old
versions despite a pinned Foundry source render. No credentials or mutation.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request

URI = "https://api.github.com/repos/truenas/apps/contents/trains/community/minecraft?ref=main"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def version_inventory(rows: object) -> list[str]:
    if type(rows) is not list or len(rows) > 1000:
        raise ValueError("CATALOG_LIST_INVALID")
    versions = []
    for row in rows:
        if type(row) is not dict:
            raise ValueError("CATALOG_LIST_INVALID")
        name = row.get("name")
        kind = row.get("type")
        if not isinstance(name, str) or kind not in {"dir", "file"}:
            raise ValueError("CATALOG_LIST_INVALID")
        if kind == "dir" and VERSION.fullmatch(name):
            versions.append(name)
    if not versions or len(set(versions)) != len(versions):
        raise ValueError("CATALOG_LIST_AMBIGUOUS")
    return sorted(versions)


def evaluate(rows: object, expected: str) -> dict:
    if not isinstance(expected, str) or not VERSION.fullmatch(expected):
        raise ValueError("INVALID_PINNED_VERSION")
    available = version_inventory(rows)
    return {
        "schema": "collage.official-catalog-preflight/1",
        "classification": "PRE_KVM_CATALOG_VERSION_AVAILABLE"
                          if expected in available else "PRE_KVM_CATALOG_DRIFT",
        "expected_version": expected,
        "visible_versions": available,
        "guest_catalog_observed": False,
        "live_minecraft_qualified": False,
        "world_mutated": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected", required=True)
    a = p.parse_args()
    req = urllib.request.Request(URI, headers={
        "User-Agent": "SupraCraft-COLLAGE-immutable-catalog-preflight",
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as stream:
            payload = stream.read(512 * 1024 + 1)
        if len(payload) > 512 * 1024:
            raise ValueError("CATALOG_LIST_OVERSIZED")
        row = evaluate(json.loads(payload), a.expected)
        status = 0 if row["classification"] == "PRE_KVM_CATALOG_VERSION_AVAILABLE" else 2
    except (OSError, ValueError, urllib.error.HTTPError):
        row = {
            "schema": "collage.official-catalog-preflight/1",
            "classification": "PRE_KVM_CATALOG_INCONCLUSIVE",
            "reason": "OFFICIAL_READONLY_CATALOG_UNAVAILABLE_OR_UNEXPECTED",
            "guest_catalog_observed": False, "world_mutated": False,
        }
        status = 3
    print(json.dumps(row, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main())
