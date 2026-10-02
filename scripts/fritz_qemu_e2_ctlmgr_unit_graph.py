#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D3 ctlmgr unit-graph recovery."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import shlex

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load base probe")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

_STARTUP_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_e2_startup_semantics.py")
_STARTUP_SPEC = importlib.util.spec_from_file_location("fritz_startup", _STARTUP_SCRIPT)
if _STARTUP_SPEC is None or _STARTUP_SPEC.loader is None:
    raise RuntimeError("unable to load startup reducer")
startup = importlib.util.module_from_spec(_STARTUP_SPEC)
_STARTUP_SPEC.loader.exec_module(startup)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-ctlmgr-unit-graph/v1"
UNIT_ROOT = pathlib.PurePosixPath("/lib/systemd/system")
CTLMGR_UNIT = "ctlmgr.service"

UNIT_RE = re.compile(
    r"^[A-Za-z0-9_.@:-]+\.(?:service|target|socket|mount|path|timer)$"
)
DEPENDENCY_KEYS = {
    "After", "Before", "Wants", "Requires", "WantedBy", "RequiredBy",
    "PartOf", "Conflicts", "BindsTo",
}
EXEC_KEYS = {"ExecStart", "ExecStartPre", "ExecStartPost"}
PATH_KEYS = {"EnvironmentFile", "PIDFile"}
SAFE_SERVICE_TYPES = {"simple", "forking", "oneshot", "notify", "dbus", "idle", "exec"}


def parse_ini(path: pathlib.Path) -> dict[str, list[tuple[str, str]]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    if "\x00" in text:
        return {}
    section = ""
    out: dict[str, list[tuple[str, str]]] = {}
    logical = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if logical:
            logical += line.lstrip()
        else:
            logical = line
        if logical.endswith("\\"):
            logical = logical[:-1]
            continue
        line = logical.strip()
        logical = ""
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1][:64]
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        out.setdefault(section, []).append((key, value))
    return out


def dependency_units(value: str) -> list[str]:
    units: list[str] = []
    for token in value.split():
        token = token.strip()
        if UNIT_RE.fullmatch(token):
            units.append(token)
    return sorted(set(units))


def safe_exec_shape(value: str) -> dict:
    try:
        words = shlex.split(value, comments=False, posix=True)
    except ValueError:
        words = value.split()
    if not words:
        return {"executable": None, "args": []}
    first = words[0]
    # systemd permits prefix characters before an executable.
    while first and first[0] in "-+!@:":
        first = first[1:]
    executable = (
        first if first.startswith("/") and len(first) <= 512
        else startup.token_kind(first)
    )
    args = [startup.token_kind(x) for x in words[1:16]]
    return {
        "executable": executable,
        "argCount": max(0, len(words) - 1),
        "args": args,
    }


def safe_path_values(value: str) -> list[dict]:
    out: list[dict] = []
    for token in value.split():
        t = token.lstrip("-")
        if t.startswith("/") and len(t) <= 512:
            out.append({"path": t, "optional": token.startswith("-")})
    return out


def reduce_ctlmgr_unit(root: pathlib.Path) -> dict:
    path = root / str(UNIT_ROOT).lstrip("/") / CTLMGR_UNIT
    if not path.exists():
        return {"present": False, "path": str(UNIT_ROOT / CTLMGR_UNIT)}
    parsed = parse_ini(path)
    reduced: dict = {
        "present": True,
        "path": str(UNIT_ROOT / CTLMGR_UNIT),
        "dependencies": [],
        "exec": [],
        "paths": [],
        "serviceType": None,
    }
    for section, entries in parsed.items():
        for key, value in entries:
            if key in DEPENDENCY_KEYS:
                for unit in dependency_units(value):
                    reduced["dependencies"].append({
                        "section": section,
                        "key": key,
                        "unit": unit,
                    })
            elif key in EXEC_KEYS:
                reduced["exec"].append({
                    "section": section,
                    "key": key,
                    **safe_exec_shape(value),
                })
            elif key in PATH_KEYS:
                for item in safe_path_values(value):
                    reduced["paths"].append({
                        "section": section,
                        "key": key,
                        **item,
                    })
            elif key == "Type" and value in SAFE_SERVICE_TYPES:
                reduced["serviceType"] = value
    reduced["dependencies"] = sorted(
        {json.dumps(x, sort_keys=True): x for x in reduced["dependencies"]}.values(),
        key=lambda x: (x["section"], x["key"], x["unit"]),
    )
    return reduced


def reverse_references(root: pathlib.Path) -> list[dict]:
    unit_root = root / str(UNIT_ROOT).lstrip("/")
    out: list[dict] = []
    if not unit_root.exists():
        return out

    for path in unit_root.rglob("*"):
        try:
            rel = "/" + str(path.relative_to(root)).replace(os.sep, "/")
        except ValueError:
            continue
        if path.is_symlink():
            try:
                target = os.readlink(path)
            except OSError:
                continue
            if pathlib.PurePosixPath(target).name == CTLMGR_UNIT or path.name == CTLMGR_UNIT:
                out.append({
                    "source": rel,
                    "relation": "symlink",
                    "targetUnit": CTLMGR_UNIT,
                    "symlinkTarget": target if len(target) <= 512 else None,
                })
            continue
        if not path.is_file() or path.name == CTLMGR_UNIT:
            continue
        parsed = parse_ini(path)
        for section, entries in parsed.items():
            for key, value in entries:
                if key not in DEPENDENCY_KEYS:
                    continue
                units = dependency_units(value)
                if CTLMGR_UNIT in units:
                    out.append({
                        "source": rel,
                        "section": section,
                        "key": key,
                        "relation": "unit-dependency",
                        "targetUnit": CTLMGR_UNIT,
                    })
    unique = {json.dumps(x, sort_keys=True): x for x in out}
    return [unique[k] for k in sorted(unique)]


def candidate_supervisor_targets(ctlmgr: dict, refs: list[dict]) -> list[dict]:
    targets: list[dict] = []
    for dep in ctlmgr.get("dependencies", []):
        if dep["key"] in ("WantedBy", "RequiredBy") and dep["unit"].endswith(".target"):
            targets.append({
                "target": dep["unit"],
                "evidence": f"ctlmgr.service:{dep['key']}",
            })
    for ref in refs:
        src_name = pathlib.PurePosixPath(ref["source"]).name
        # target.wants/ctlmgr.service or direct target-unit dependency
        parts = pathlib.PurePosixPath(ref["source"]).parts
        for part in parts:
            if part.endswith(".target.wants") or part.endswith(".target.requires"):
                targets.append({
                    "target": part.rsplit(".", 1)[0],
                    "evidence": "unit-symlink-directory",
                })
        if src_name.endswith(".target") and ref.get("relation") == "unit-dependency":
            targets.append({
                "target": src_name,
                "evidence": f"{src_name}:{ref.get('key')}",
            })
    unique = {json.dumps(x, sort_keys=True): x for x in targets}
    return [unique[k] for k in sorted(unique)]


def run_probe(args: argparse.Namespace) -> dict:
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

    ctlmgr = reduce_ctlmgr_unit(root)
    refs = reverse_references(root)
    targets = candidate_supervisor_targets(ctlmgr, refs)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "CTLMGR_UNIT_GRAPH_COMPLETE",
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
        "ctlmgrUnit": ctlmgr,
        "reverseReferences": refs,
        "candidateSupervisorTargets": targets,
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "rawUnitContentPublished": False,
            "arbitraryUnitStringsPublished": False,
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
                "rawUnitContentPublished": False,
                "arbitraryUnitStringsPublished": False,
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
