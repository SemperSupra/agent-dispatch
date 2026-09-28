#!/usr/bin/env python3
"""Diff two github-runner-capability/v1 receipts without scalar scoring."""
from __future__ import annotations
import argparse
import json
import pathlib
from typing import Any


def _caps(receipt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in receipt.get("capabilities", []) if "name" in c}


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    b = _caps(before)
    a = _caps(after)
    names = sorted(set(b) | set(a))
    changes = []
    for name in names:
        left, right = b.get(name), a.get(name)
        if left is None:
            changes.append({"name": name, "kind": "new-capability-observation", "after": right})
            continue
        if right is None:
            changes.append({"name": name, "kind": "capability-disappeared", "before": left})
            continue
        keys = ("observed", "installed", "callable", "exercised", "oracleSatisfied", "classification")
        delta = {key: [left.get(key), right.get(key)] for key in keys if left.get(key) != right.get(key)}
        if delta:
            kind = "capability-state-changed"
            if left.get("oracleSatisfied") is True and right.get("oracleSatisfied") is False:
                kind = "oracle-regression"
            changes.append({"name": name, "kind": kind, "delta": delta})

    return {
        "schema": "github-runner-capability-diff/v1",
        "identity": {
            "requested_label_before": before.get("provenance", {}).get("requested_label"),
            "requested_label_after": after.get("provenance", {}).get("requested_label"),
            "image_version_before": before.get("provenance", {}).get("image_version"),
            "image_version_after": after.get("provenance", {}).get("image_version"),
            "probe_version_before": before.get("provenance", {}).get("probe_version"),
            "probe_version_after": after.get("provenance", {}).get("probe_version"),
        },
        "resource_observations": {
            "cpu_logical": [
                before.get("resources", {}).get("cpu", {}).get("logical_processors"),
                after.get("resources", {}).get("cpu", {}).get("logical_processors"),
            ],
            "memory_total_bytes": [
                before.get("resources", {}).get("memory", {}).get("total_bytes"),
                after.get("resources", {}).get("memory", {}).get("total_bytes"),
            ],
        },
        "capability_changes": changes,
        "note": "resource differences are observations, not provider-contract regressions",
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--out", required=True)
    args = p.parse_args()
    before = json.loads(pathlib.Path(args.before).read_text())
    after = json.loads(pathlib.Path(args.after).read_text())
    result = compare(before, after)
    pathlib.Path(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
