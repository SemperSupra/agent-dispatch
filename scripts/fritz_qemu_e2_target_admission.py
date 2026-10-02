#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D5 exact target-admission graph recovery."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-target-admission-graph/v1"
UNIT_ROOT = "/lib/systemd/system"
TARGETS = ("network.target", "prodtest-network.target")
CTLMGR = "ctlmgr.service"
SAFE_KEYS = ("Wants", "Requires", "After", "Before", "WantedBy")


def parse_unit(path: pathlib.Path) -> dict:
    data = path.read_text(encoding="utf-8", errors="replace")
    if "\x00" in data:
        return {}
    out: dict[str, list[str]] = {k: [] for k in SAFE_KEYS}
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in SAFE_KEYS:
            continue
        tokens = []
        for token in value.split():
            if re.fullmatch(r"[A-Za-z0-9_.@:-]+\.(?:service|target|socket|mount|path|timer|slice)", token):
                tokens.append(token)
        out[key].extend(tokens)
    return {k: sorted(set(v)) for k, v in out.items() if v}


def symlink_memberships(unit_root: pathlib.Path, target: str) -> dict[str, list[str]]:
    result = {"wants": [], "requires": []}
    for relation, suffix in (("wants", ".wants"), ("requires", ".requires")):
        d = unit_root / f"{target}{suffix}"
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if not p.is_symlink():
                continue
            name = p.name
            if re.fullmatch(r"[A-Za-z0-9_.@:-]+\.(?:service|target|socket|mount|path|timer|slice)", name):
                result[relation].append(name)
    return result


def recover(root: pathlib.Path) -> dict:
    unit_root = root / UNIT_ROOT.lstrip("/")
    if not unit_root.is_dir():
        raise RuntimeError("unit root absent")

    parsed: dict[str, dict] = {}
    for p in sorted(unit_root.iterdir()):
        if not p.is_file() or p.is_symlink():
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.(?:service|target|socket|mount|path|timer|slice)", p.name):
            continue
        parsed[p.name] = parse_unit(p)

    targets: dict[str, dict] = {}
    for target in TARGETS:
        if target not in parsed:
            raise RuntimeError(f"target unit absent: {target}")
        admitted = set()
        admission_edges = []

        for unit, meta in parsed.items():
            if target in meta.get("WantedBy", []):
                admitted.add(unit)
                admission_edges.append({
                    "unit": unit,
                    "target": target,
                    "mechanism": "WantedBy",
                })

        links = symlink_memberships(unit_root, target)
        for relation in ("wants", "requires"):
            for unit in links[relation]:
                admitted.add(unit)
                admission_edges.append({
                    "unit": unit,
                    "target": target,
                    "mechanism": f"target.{relation}",
                })

        target_meta = parsed[target]
        direct_deps = {
            k: target_meta.get(k, [])
            for k in ("Wants", "Requires", "After", "Before")
            if target_meta.get(k)
        }
        for key in ("Wants", "Requires"):
            for unit in target_meta.get(key, []):
                admitted.add(unit)
                admission_edges.append({
                    "unit": unit,
                    "target": target,
                    "mechanism": f"target-{key}",
                })

        edges_unique = {
            json.dumps(x, sort_keys=True): x for x in admission_edges
        }
        targets[target] = {
            "present": True,
            "directDependencies": direct_deps,
            "symlinkMembership": links,
            "admissionEdges": [edges_unique[k] for k in sorted(edges_unique)],
            "admittedUnits": sorted(admitted),
            "admittedUnitCount": len(admitted),
            "ctlmgrAdmitted": CTLMGR in admitted,
            "ctlmgrAdmissionMechanisms": sorted({
                x["mechanism"] for x in admission_edges if x["unit"] == CTLMGR
            }),
        }

    eligible = [
        (meta["admittedUnitCount"], target)
        for target, meta in targets.items()
        if meta["ctlmgrAdmitted"]
    ]
    recommendation = sorted(eligible)[0][1] if eligible else None

    return {
        "targets": targets,
        "mechanicalNarrowestCtlmgrTarget": recommendation,
        "selectionRule": "minimum admittedUnitCount among exact targets that admit ctlmgr.service; lexical tie-break",
    }


def run_probe(args) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
    for p in (firmware.parent, payload, roots_dir, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url, firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    root = base.select_root(roots)
    graph = recover(root)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "E2_TARGET_ADMISSION_GRAPH_RECOVERED",
        "oracleSatisfied": True,
        "target": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "extraction": {
            "outerMemberCount": len(outer),
            "squashfsRootCount": len(roots),
            "selectedRootRegularFileCount": base.root_file_count(root),
        },
        "graph": graph,
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "rawUnitContentsPublished": False,
            "arbitraryUnitValuesPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url", required=True)
    p.add_argument("--expected-size", required=True, type=int)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0
    except Exception as exc:
        receipt = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawFirmwarePublished": False,
                "rootfsPublished": False,
                "rawUnitContentsPublished": False,
                "arbitraryUnitValuesPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
