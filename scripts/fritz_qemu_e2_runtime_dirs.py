#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D4 runtime-directory contract recovery."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import stat

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-runtime-directory-contract/v1"

FIXED_PATHS = {
    "tmp": "/tmp",
    "var_tmp": "/var/tmp",
    "run": "/run",
    "var_run": "/var/run",
    "dev_shm": "/dev/shm",
    "supervisor_control_socket": "/tmp/supervisor.ctrl.socket",
}

SCAN_ROOTS = (
    "/etc/boot.d",
    "/etc/init.d",
    "/lib/systemd/system",
)

SAFE_OPERATIONS = {
    "mkdir": re.compile(r"(?<![A-Za-z0-9_])mkdir(?![A-Za-z0-9_])"),
    "mount": re.compile(r"(?<![A-Za-z0-9_])mount(?![A-Za-z0-9_])"),
    "symlink": re.compile(r"(?<![A-Za-z0-9_])ln(?![A-Za-z0-9_])"),
    "remove": re.compile(r"(?<![A-Za-z0-9_])rm(?![A-Za-z0-9_])"),
    "chmod": re.compile(r"(?<![A-Za-z0-9_])chmod(?![A-Za-z0-9_])"),
    "chown": re.compile(r"(?<![A-Za-z0-9_])chown(?![A-Za-z0-9_])"),
    "tmpfiles": re.compile(r"(?i)tmpfiles"),
    "unit_mount": re.compile(r"(?i)TemporaryFileSystem|RequiresMountsFor|BindPaths|ReadWritePaths"),
}


def _mode_string(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def path_metadata(root: pathlib.Path, guest_path: str) -> dict:
    path = root / guest_path.lstrip("/")
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {
            "path": guest_path,
            "exists": False,
            "type": "missing",
            "mode": None,
            "symlinkTarget": None,
        }

    if stat.S_ISDIR(st.st_mode):
        kind = "directory"
    elif stat.S_ISLNK(st.st_mode):
        kind = "symlink"
    elif stat.S_ISREG(st.st_mode):
        kind = "regular"
    elif stat.S_ISSOCK(st.st_mode):
        kind = "socket"
    elif stat.S_ISCHR(st.st_mode):
        kind = "char-device"
    elif stat.S_ISBLK(st.st_mode):
        kind = "block-device"
    elif stat.S_ISFIFO(st.st_mode):
        kind = "fifo"
    else:
        kind = "other"

    target = None
    if kind == "symlink":
        try:
            raw = os.readlink(path)
        except OSError:
            raw = ""
        if raw and len(raw) <= 512 and "\x00" not in raw:
            target = raw

    return {
        "path": guest_path,
        "exists": True,
        "type": kind,
        "mode": _mode_string(st.st_mode),
        "symlinkTarget": target,
    }


def _path_mentioned(line: str, guest_path: str) -> bool:
    # Match the fixed path only at a path boundary so /tmp does not falsely
    # match /tmpfoo. No arbitrary neighboring text is retained.
    pattern = re.compile(re.escape(guest_path) + r"(?=$|[\s/'\";:,)=}\]])")
    return bool(pattern.search(line))


def classify_line(line: str) -> list[str]:
    return sorted(
        name for name, pattern in SAFE_OPERATIONS.items()
        if pattern.search(line)
    ) or ["reference"]


def scan_materialization_relations(root: pathlib.Path) -> list[dict]:
    relations: list[dict] = []
    for guest_root in SCAN_ROOTS:
        host_root = root / guest_root.lstrip("/")
        if not host_root.exists():
            continue
        for path in sorted(host_root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                if path.stat().st_size > 512 * 1024:
                    continue
                data = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "\x00" in data:
                continue
            source = "/" + str(path.relative_to(root)).replace(os.sep, "/")
            for line in data.splitlines():
                for key, guest_path in FIXED_PATHS.items():
                    if not _path_mentioned(line, guest_path):
                        continue
                    for operation in classify_line(line):
                        relations.append({
                            "source": source,
                            "fixedPathKey": key,
                            "fixedPath": guest_path,
                            "operation": operation,
                        })
    unique = {json.dumps(x, sort_keys=True): x for x in relations}
    return [unique[k] for k in sorted(unique)]


def inferred_fixture_requirements(metadata: dict[str, dict], relations: list[dict]) -> list[dict]:
    """Derive only filesystem prerequisites mechanically supported by metadata."""
    requirements: list[dict] = []
    tmp = metadata["tmp"]
    var_tmp = metadata["var_tmp"]
    if not tmp["exists"]:
        requirements.append({
            "path": "/tmp",
            "requirement": "materialize-runtime-path",
            "reason": "absent-in-extracted-root",
        })
    elif tmp["type"] == "symlink" and tmp["symlinkTarget"]:
        requirements.append({
            "path": "/tmp",
            "requirement": "preserve-symlink-target",
            "target": tmp["symlinkTarget"],
            "reason": "exact-root-symlink",
        })
    if not var_tmp["exists"]:
        requirements.append({
            "path": "/var/tmp",
            "requirement": "materialize-runtime-path",
            "reason": "absent-in-extracted-root",
        })

    operation_by_key: dict[str, set[str]] = {}
    for rel in relations:
        operation_by_key.setdefault(rel["fixedPathKey"], set()).add(rel["operation"])
    for key in ("tmp", "var_tmp", "run", "var_run", "dev_shm"):
        if operation_by_key.get(key):
            requirements.append({
                "path": FIXED_PATHS[key],
                "requirement": "boot-materialization-observed",
                "operations": sorted(operation_by_key[key]),
                "reason": "fixed-path-init-reference",
            })

    unique = {json.dumps(x, sort_keys=True): x for x in requirements}
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

    metadata = {
        key: path_metadata(root, path)
        for key, path in FIXED_PATHS.items()
    }
    relations = scan_materialization_relations(root)
    requirements = inferred_fixture_requirements(metadata, relations)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "E2_RUNTIME_DIRECTORY_CONTRACT_RECOVERED",
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
        "fixedPathMetadata": metadata,
        "materializationRelations": relations,
        "fixtureRequirements": requirements,
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "rawScriptContentPublished": False,
            "arbitraryScriptStringsPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "runtimeFixtureCreated": False,
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
                "rawScriptContentPublished": False,
                "arbitraryScriptStringsPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "runtimeFixtureCreated": False,
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
