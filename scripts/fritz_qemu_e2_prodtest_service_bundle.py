#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D6 prodtest service-bundle contract recovery."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import shlex

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-prodtest-service-bundle/v1"
UNIT_ROOT = "/lib/systemd/system"
TARGET = "prodtest-network.target"
UNITS = (
    "avmipcd.service",
    "ctlmgr.service",
    "dsld.service",
    "multid.service",
    "net_basic.service",
    "network-pre.target",
)
DEPENDENCY_KEYS = (
    "After", "Before", "Wants", "Requires", "PartOf", "BindsTo",
    "Conflicts", "WantedBy", "RequiredBy",
)
EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost")
PATH_KEYS = ("EnvironmentFile", "PIDFile")
SAFE_SERVICE_TYPES = {"simple", "forking", "oneshot", "notify", "dbus", "idle", "exec"}
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|target|socket|mount|path|timer|slice)$")
CONDITION_KEY_RE = re.compile(r"^(?:Condition|Assert)[A-Za-z0-9]+$")


def parse_ini(path: pathlib.Path) -> dict[str, list[tuple[str, str]]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "\x00" in text:
        return {}
    section = ""
    out: dict[str, list[tuple[str, str]]] = {}
    logical = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        logical = (logical + line.lstrip()) if logical else line
        if logical.endswith("\\"):
            logical = logical[:-1]
            continue
        line = logical.strip()
        logical = ""
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1][:64]
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out.setdefault(section, []).append((key.strip(), value.strip()))
    return out


def unit_tokens(value: str) -> list[str]:
    return sorted({t for t in value.split() if UNIT_RE.fullmatch(t)})


def safe_exec(value: str) -> dict:
    try:
        words = shlex.split(value, comments=False, posix=True)
    except ValueError:
        words = value.split()
    if not words:
        return {"executable": None, "argCount": 0, "args": []}
    first = words[0]
    while first and first[0] in "-+!@:":
        first = first[1:]
    exe = first if first.startswith("/") and len(first) <= 512 else "opaque"
    args = []
    for token in words[1:16]:
        if token.startswith("/") and len(token) <= 512:
            args.append({"kind": "absolute-path", "value": token})
        elif UNIT_RE.fullmatch(token):
            args.append({"kind": "unit", "value": token})
        elif re.fullmatch(r"--?[A-Za-z0-9_.-]+", token):
            args.append({"kind": "option", "value": token})
        else:
            args.append({"kind": "opaque", "sha256": hashlib.sha256(token.encode()).hexdigest(), "length": len(token)})
    return {"executable": exe, "argCount": max(0, len(words)-1), "args": args}


def safe_paths(value: str) -> list[dict]:
    out = []
    for token in value.split():
        optional = token.startswith("-")
        token = token.lstrip("-")
        if token.startswith("/") and len(token) <= 512:
            out.append({"path": token, "optional": optional})
    return out


def safe_condition(key: str, value: str) -> dict:
    negated = value.startswith("!")
    operand = value[1:] if negated else value
    if operand.startswith("/") and len(operand) <= 512:
        reduced = {"kind": "absolute-path", "value": operand}
    elif UNIT_RE.fullmatch(operand):
        reduced = {"kind": "unit", "value": operand}
    elif re.fullmatch(r"(?:yes|no|true|false|0|1)", operand, re.I):
        reduced = {"kind": "boolean", "value": operand.lower()}
    else:
        reduced = {
            "kind": "opaque",
            "sha256": hashlib.sha256(operand.encode()).hexdigest(),
            "length": len(operand),
        }
    return {"key": key, "negated": negated, "operand": reduced}


def reduce_unit(root: pathlib.Path, name: str) -> dict:
    path = root / UNIT_ROOT.lstrip("/") / name
    if not path.is_file():
        return {"name": name, "present": False}
    parsed = parse_ini(path)
    out = {
        "name": name,
        "present": True,
        "serviceType": None,
        "dependencies": [],
        "exec": [],
        "paths": [],
        "conditions": [],
    }
    for section, entries in parsed.items():
        for key, value in entries:
            if key == "Type" and value in SAFE_SERVICE_TYPES:
                out["serviceType"] = value
            elif key in DEPENDENCY_KEYS:
                for unit in unit_tokens(value):
                    out["dependencies"].append({"section": section, "key": key, "unit": unit})
            elif key in EXEC_KEYS:
                out["exec"].append({"section": section, "key": key, **safe_exec(value)})
            elif key in PATH_KEYS:
                for item in safe_paths(value):
                    out["paths"].append({"section": section, "key": key, **item})
            elif CONDITION_KEY_RE.fullmatch(key):
                out["conditions"].append({"section": section, **safe_condition(key, value)})
    for key in ("dependencies", "exec", "paths", "conditions"):
        unique = {json.dumps(x, sort_keys=True): x for x in out[key]}
        out[key] = [unique[k] for k in sorted(unique)]
    return out


def derive_graph(units: dict[str, dict]) -> dict:
    members = set(units)
    edges = []
    for source, meta in units.items():
        for dep in meta.get("dependencies", []):
            if dep["unit"] in members:
                edges.append({
                    "source": source,
                    "relation": dep["key"],
                    "target": dep["unit"],
                })
    unique = {json.dumps(x, sort_keys=True): x for x in edges}
    edges = [unique[k] for k in sorted(unique)]

    ctl = units["ctlmgr.service"]
    hard = sorted({
        d["unit"] for d in ctl.get("dependencies", [])
        if d["key"] in ("Requires", "BindsTo") and d["unit"] in members
    })
    wants = sorted({
        d["unit"] for d in ctl.get("dependencies", [])
        if d["key"] == "Wants" and d["unit"] in members
    })
    ordering = sorted({
        d["unit"] for d in ctl.get("dependencies", [])
        if d["key"] == "After" and d["unit"] in members
    })
    exec_watch = sorted({
        item["executable"]
        for meta in units.values()
        for item in meta.get("exec", [])
        if isinstance(item.get("executable"), str) and item["executable"].startswith("/")
    })
    return {
        "edges": edges,
        "ctlmgr": {
            "hardRequirements": hard,
            "softWants": wants,
            "orderingPredecessors": ordering,
            "conditions": ctl.get("conditions", []),
            "paths": ctl.get("paths", []),
        },
        "nextRuntimeExecWatchlist": exec_watch,
        "interpretationRule": "After/Before are ordering only; only Requires/BindsTo/Condition/Assert are hard activation gates.",
    }


def recover(root: pathlib.Path) -> dict:
    unit_root = root / UNIT_ROOT.lstrip("/")
    if not unit_root.is_dir():
        raise RuntimeError("unit root absent")
    units = {name: reduce_unit(root, name) for name in UNITS}
    missing = sorted(name for name, meta in units.items() if not meta.get("present"))
    return {
        "target": TARGET,
        "units": units,
        "missingUnits": missing,
        "graph": derive_graph(units),
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
    bundle = recover(root)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "E2_PRODTEST_SERVICE_BUNDLE_RECOVERED",
        "oracleSatisfied": not bundle["missingUnits"],
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
        "bundle": bundle,
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
    receipt = pathlib.Path(args.receipt)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = run_probe(args)
        rc = 0 if data["oracleSatisfied"] else 2
    except Exception as exc:
        data = {
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
    receipt.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": data["classification"], "oracleSatisfied": data["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
