#!/usr/bin/env python3
"""Apply and qualify a public-safe declarative overlay to an ephemeral FRITZ root.

M1 is intentionally narrow:
- exact stock image is downloaded and verified;
- rootfs is extracted ephemerally;
- overlay operations may create new paths only under /opt/supra;
- existing target paths may not be replaced;
- qemu-user-static is copied as harness scaffolding and excluded from overlay
  identity;
- only a sanitized receipt is durable.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-instrumented-overlay-m1/v1"
QEMU_GUEST_PATH = "/usr/bin/qemu-mips-static"
CPU_PROFILE = "24KEc"
ALLOWED_PREFIX = "/opt/supra/"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return base.sha256_file(path)


def canonical_sha256(value: object) -> str:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256_bytes(data)


def validate_guest_destination(path: str) -> pathlib.PurePosixPath:
    p = pathlib.PurePosixPath(path)
    if not p.is_absolute():
        raise ValueError("overlay destination must be absolute")
    if ".." in p.parts:
        raise ValueError("overlay destination may not contain parent traversal")
    if not path.startswith(ALLOWED_PREFIX):
        raise ValueError(f"M1 overlay destination must be below {ALLOWED_PREFIX}")
    return p


def parse_mode(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("0"):
        raise ValueError("mode must be an octal string such as 0755")
    mode = int(value, 8)
    if mode < 0 or mode > 0o7777:
        raise ValueError("invalid mode")
    return mode


def load_manifest(path: pathlib.Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schemaVersion") != 1:
        raise ValueError("unsupported overlay schemaVersion")
    ops = value.get("operations")
    if not isinstance(ops, list) or not ops:
        raise ValueError("overlay must contain at least one operation")
    for op in ops:
        if op.get("op") != "copy_public_file":
            raise ValueError("M1 supports copy_public_file only")
        validate_guest_destination(op.get("destination", ""))
        parse_mode(op.get("mode", ""))
        if op.get("requireDestinationAbsent") is not True:
            raise ValueError("M1 requires requireDestinationAbsent=true")
        src = pathlib.PurePosixPath(op.get("source", ""))
        if src.is_absolute() or ".." in src.parts:
            raise ValueError("overlay source must be repository-relative and traversal-free")
    if value.get("semantics", {}).get("stockSemanticsExpectedToChange") is not False:
        raise ValueError("M1 observability overlay must declare no expected stock semantic change")
    return value


def file_state(path: pathlib.Path) -> dict:
    try:
        st = path.lstat()
    except OSError:
        return {"exists": False}
    state = {
        "exists": True,
        "kind": (
            "file" if stat.S_ISREG(st.st_mode)
            else "dir" if stat.S_ISDIR(st.st_mode)
            else "symlink" if stat.S_ISLNK(st.st_mode)
            else "other"
        ),
        "mode": oct(stat.S_IMODE(st.st_mode)),
    }
    if stat.S_ISREG(st.st_mode):
        state["bytes"] = st.st_size
        state["sha256"] = sha256_file(path)
    elif stat.S_ISLNK(st.st_mode):
        state["target"] = os.readlink(path)
    return state


def apply_overlay(
    root: pathlib.Path,
    manifest: dict,
    repo_root: pathlib.Path,
) -> list[dict]:
    changes: list[dict] = []
    for op in manifest["operations"]:
        guest = validate_guest_destination(op["destination"])
        destination = root / str(guest).lstrip("/")
        before = file_state(destination)
        if before["exists"]:
            raise RuntimeError(
                f"M1 refuses to replace an existing target path: {op['destination']}"
            )
        source = (repo_root / op["source"]).resolve()
        try:
            source.relative_to(repo_root.resolve())
        except ValueError as exc:
            raise RuntimeError("overlay source escaped repository root") from exc
        if not source.is_file():
            raise RuntimeError(f"overlay source missing: {op['source']}")

        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(parse_mode(op["mode"]))
        after = file_state(destination)
        changes.append({
            "operation": op["op"],
            "source": op["source"],
            "destination": op["destination"],
            "before": before,
            "after": after,
        })
    return changes


def prepare_qemu(root: pathlib.Path) -> dict:
    source = shutil.which("qemu-mips-static")
    if not source:
        raise RuntimeError("qemu-mips-static not installed")
    destination = root / QEMU_GUEST_PATH.lstrip("/")
    before = file_state(destination)
    if before["exists"]:
        raise RuntimeError("harness qemu path unexpectedly exists in stock root")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return {
        "path": QEMU_GUEST_PATH,
        "kind": "host-harness-scaffolding",
        "before": before,
        "after": file_state(destination),
        "includedInOverlayIdentity": False,
    }


def execute_helper(root: pathlib.Path, guest_path: str) -> dict:
    cp = subprocess.run(
        [
            "sudo", "-n", "chroot", str(root),
            QEMU_GUEST_PATH, "-cpu", CPU_PROFILE,
            "/bin/busybox", "sh", guest_path,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env={"PATH": "/bin:/sbin:/usr/bin:/usr/sbin", "HOME": "/", "LANG": "C", "LC_ALL": "C"},
    )
    parsed = None
    if cp.returncode == 0:
        try:
            parsed = json.loads(cp.stdout.strip())
        except json.JSONDecodeError:
            parsed = None
    expected = {
        "schemaVersion": 1,
        "helper": "fritz-observe-supervisor/v1",
    }
    valid = (
        isinstance(parsed, dict)
        and parsed.get("schemaVersion") == expected["schemaVersion"]
        and parsed.get("helper") == expected["helper"]
        and isinstance(parsed.get("supervisorControlSocket"), bool)
    )
    return {
        "guestPath": guest_path,
        "cpuProfile": CPU_PROFILE,
        "exitCode": cp.returncode,
        "stdoutBytes": len(cp.stdout.encode("utf-8", errors="replace")),
        "stderrBytes": len(cp.stderr.encode("utf-8", errors="replace")),
        "parsedSafeResult": parsed if valid else None,
        "safeResultValidated": valid,
    }


def run_probe(args: argparse.Namespace) -> dict:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    manifest_path = (repo_root / args.manifest).resolve()
    manifest = load_manifest(manifest_path)

    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
    for p in (firmware.parent, payload, roots_dir, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url,
        firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    root = base.select_root(roots)

    stock_count = base.root_file_count(root)
    manifest_hash = canonical_sha256(manifest)
    changes = apply_overlay(root, manifest, repo_root)
    qemu_scaffold = prepare_qemu(root)

    changed_paths = sorted(item["destination"] for item in changes)
    helper_path = changed_paths[0]
    execution = execute_helper(root, helper_path)

    all_before_absent = all(not c["before"]["exists"] for c in changes)
    stock_files_replaced = any(c["before"]["exists"] for c in changes)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": (
            "M1_OBSERVABILITY_OVERLAY_PASS"
            if execution["safeResultValidated"] and not stock_files_replaced
            else "M1_OVERLAY_ORACLE_FAILURE"
        ),
        "oracleSatisfied": bool(
            execution["safeResultValidated"] and not stock_files_replaced
        ),
        "stockTarget": {
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
            "outerMemberCount": len(outer),
            "squashfsRootCount": len(roots),
            "selectedRootRegularFileCountBeforeOverlay": stock_count,
        },
        "overlay": {
            "overlayId": manifest["overlayId"],
            "manifestSha256": manifest_hash,
            "stockSemanticsExpectedToChange": False,
            "changedPaths": changed_paths,
            "allDestinationsAbsentInStock": all_before_absent,
            "stockFilesReplaced": stock_files_replaced,
            "changes": changes,
        },
        "harnessScaffolding": qemu_scaffold,
        "execution": execution,
        "disposal": {
            "derivedRootDurable": False,
            "cleanupByEphemeralRunner": True,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "modifiedRootfsPublished": False,
            "proprietaryBinaryModified": False,
            "stockFileReplaced": stock_files_replaced,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "externalNetworkRequiredForGuestExecution": False,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url", required=True)
    p.add_argument("--expected-size", required=True, type=int)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0 if receipt.get("oracleSatisfied") else 2
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
                "modifiedRootfsPublished": False,
                "proprietaryBinaryModified": False,
                "stockFileReplaced": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkRequiredForGuestExecution": False,
            },
        }
        rc = 3

    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "classification": receipt["classification"],
        "oracleSatisfied": receipt["oracleSatisfied"],
    }, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
