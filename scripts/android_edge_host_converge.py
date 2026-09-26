#!/usr/bin/env python3
"""Cross-platform Android host environment converger.

Implements observe -> plan -> apply -> verify with tool-owned state so setup is
repeatable, reversible, and idempotent on Windows, Linux, and macOS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from typing import Any

PLATFORM_TOOLS_VERSION = "37.0.1"
SCHEMA = "android-edge-host-converger/v1"

ARCHIVES = {
    "Windows": [
        f"https://dl.google.com/android/repository/platform-tools_r{PLATFORM_TOOLS_VERSION}-windows.zip",
        "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
    ],
    "Linux": [
        f"https://dl.google.com/android/repository/platform-tools_r{PLATFORM_TOOLS_VERSION}-linux.zip",
        "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
    ],
    "Darwin": [
        f"https://dl.google.com/android/repository/platform-tools_r{PLATFORM_TOOLS_VERSION}-darwin.zip",
        "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    ],
}

@dataclass
class Observation:
    schema: str
    system: str
    machine: str
    root: str
    managed_dir: str
    manifest_present: bool
    managed_adb_present: bool
    managed_fastboot_present: bool
    managed_adb_version: str | None
    system_adb: str | None
    system_fastboot: str | None

@dataclass
class Plan:
    schema: str
    action: str
    changed: bool
    reason: str
    desired_version: str
    root: str
    managed_dir: str

def _default_root() -> pathlib.Path:
    system = platform.system()
    if system == "Windows":
        base = pathlib.Path(os.environ.get("LOCALAPPDATA") or pathlib.Path.home() / "AppData" / "Local")
        return base / "AndroidEdgeApplianceKit"
    return pathlib.Path.home() / ".local" / "share" / "android-edge-appliance-kit"

def _exe(name: str) -> str:
    return name + ".exe" if platform.system() == "Windows" else name

def _run(argv: list[str], timeout: int = 20) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except Exception as exc:
        return None, "", str(exc)

def _adb_version(path: pathlib.Path) -> str | None:
    if not path.is_file():
        return None
    code, out, _ = _run([str(path), "version"])
    if code != 0:
        return None
    first = out.splitlines()[0] if out else ""
    return first or None

def observe(root: pathlib.Path) -> Observation:
    managed = root / "platform-tools"
    manifest = root / "manifest.json"
    adb = managed / _exe("adb")
    fastboot = managed / _exe("fastboot")
    return Observation(
        schema=SCHEMA,
        system=platform.system(),
        machine=platform.machine(),
        root=str(root),
        managed_dir=str(managed),
        manifest_present=manifest.is_file(),
        managed_adb_present=adb.is_file(),
        managed_fastboot_present=fastboot.is_file(),
        managed_adb_version=_adb_version(adb),
        system_adb=shutil.which("adb"),
        system_fastboot=shutil.which("fastboot"),
    )

def plan(root: pathlib.Path) -> Plan:
    obs = observe(root)
    desired = f"Android Debug Bridge version {PLATFORM_TOOLS_VERSION}"
    if obs.managed_adb_present and obs.managed_fastboot_present and obs.managed_adb_version == desired:
        return Plan(SCHEMA, "noop", False, "managed platform-tools already match desired version",
                    PLATFORM_TOOLS_VERSION, str(root), obs.managed_dir)
    return Plan(SCHEMA, "install-or-repair", True, "managed platform-tools are absent or not at desired version",
                PLATFORM_TOOLS_VERSION, str(root), obs.managed_dir)

def _download(url: str, dest: pathlib.Path) -> str:
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as r, dest.open("wb") as f:
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            f.write(chunk)
    return h.hexdigest()

def _download_archive(dest: pathlib.Path, allow_latest_fallback: bool) -> tuple[str, str]:
    system = platform.system()
    if system not in ARCHIVES:
        raise RuntimeError(f"unsupported operating system: {system}")
    urls = ARCHIVES[system]
    attempts = urls if allow_latest_fallback else urls[:1]
    errors: list[str] = []
    for url in attempts:
        try:
            return url, _download(url, dest)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("platform-tools download failed: " + " | ".join(errors))

def apply(root: pathlib.Path, allow_latest_fallback: bool = False) -> dict[str, Any]:
    p = plan(root)
    if not p.changed:
        return {"schema": SCHEMA, "operation": "apply", "changed": False, "plan": asdict(p), "verification": asdict(observe(root))}
    root.mkdir(parents=True, exist_ok=True)
    managed = root / "platform-tools"
    previous = root / ".previous-platform-tools"
    manifest = root / "manifest.json"
    with tempfile.TemporaryDirectory(prefix="android-edge-host-") as td:
        td_path = pathlib.Path(td)
        archive = td_path / "platform-tools.zip"
        url, sha256 = _download_archive(archive, allow_latest_fallback)
        extract = td_path / "extract"
        extract.mkdir()
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(extract)
        staged = extract / "platform-tools"
        if not (staged / _exe("adb")).is_file() or not (staged / _exe("fastboot")).is_file():
            raise RuntimeError("downloaded archive did not contain adb and fastboot")
        version = _adb_version(staged / _exe("adb"))
        expected = f"Android Debug Bridge version {PLATFORM_TOOLS_VERSION}"
        if version != expected:
            raise RuntimeError(f"downloaded adb version mismatch: expected {expected!r}, got {version!r}")
        if previous.exists():
            shutil.rmtree(previous)
        if managed.exists():
            managed.replace(previous)
        temp_target = root / ".platform-tools.new"
        if temp_target.exists():
            shutil.rmtree(temp_target)
        shutil.copytree(staged, temp_target)
        temp_target.replace(managed)
        manifest.write_text(json.dumps({
            "schema": SCHEMA,
            "version": PLATFORM_TOOLS_VERSION,
            "archive_url": url,
            "archive_sha256": sha256,
            "system": platform.system(),
            "machine": platform.machine(),
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verification = verify(root)
    if not verification["passed"]:
        raise RuntimeError("post-apply verification failed: " + verification["reason"])
    return {"schema": SCHEMA, "operation": "apply", "changed": True, "plan": asdict(p), "verification": verification}

def verify(root: pathlib.Path) -> dict[str, Any]:
    obs = observe(root)
    expected = f"Android Debug Bridge version {PLATFORM_TOOLS_VERSION}"
    adb_ok = obs.managed_adb_present and obs.managed_adb_version == expected
    fastboot_path = pathlib.Path(obs.managed_dir) / _exe("fastboot")
    fastboot_code, fastboot_out, fastboot_err = _run([str(fastboot_path), "--version"]) if fastboot_path.is_file() else (None, "", "missing")
    fastboot_ok = fastboot_path.is_file() and fastboot_code == 0
    passed = bool(adb_ok and fastboot_ok and obs.manifest_present)
    reason = "managed adb/fastboot and manifest satisfy desired state" if passed else "managed Android platform-tools do not satisfy desired state"
    return {
        "schema": SCHEMA,
        "operation": "verify",
        "passed": passed,
        "reason": reason,
        "observation": asdict(obs),
        "fastboot": {"exit_code": fastboot_code, "stdout": fastboot_out, "stderr": fastboot_err},
    }

def revert(root: pathlib.Path) -> dict[str, Any]:
    managed = root / "platform-tools"
    previous = root / ".previous-platform-tools"
    manifest = root / "manifest.json"
    changed = False
    if managed.exists():
        shutil.rmtree(managed)
        changed = True
    if previous.exists():
        previous.replace(managed)
        changed = True
    if manifest.exists():
        manifest.unlink()
        changed = True
    return {"schema": SCHEMA, "operation": "revert", "changed": changed, "observation": asdict(observe(root))}

def cycle(root: pathlib.Path, allow_latest_fallback: bool = False) -> dict[str, Any]:
    before = asdict(observe(root))
    first_plan = asdict(plan(root))
    first_apply = apply(root, allow_latest_fallback=allow_latest_fallback)
    first_verify = verify(root)
    second_plan = asdict(plan(root))
    second_apply = apply(root, allow_latest_fallback=allow_latest_fallback)
    second_verify = verify(root)
    reverted = revert(root)
    after_revert = asdict(observe(root))
    reapplied = apply(root, allow_latest_fallback=allow_latest_fallback)
    final_verify = verify(root)
    passed = (
        first_verify["passed"]
        and second_plan["action"] == "noop"
        and second_apply["changed"] is False
        and not after_revert["managed_adb_present"]
        and not after_revert["managed_fastboot_present"]
        and final_verify["passed"]
    )
    return {
        "schema": SCHEMA,
        "operation": "cycle",
        "passed": passed,
        "before": before,
        "first_plan": first_plan,
        "first_apply": first_apply,
        "first_verify": first_verify,
        "second_plan": second_plan,
        "second_apply": second_apply,
        "second_verify": second_verify,
        "revert": reverted,
        "after_revert": after_revert,
        "reapply": reapplied,
        "final_verify": final_verify,
    }

def contract() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "audiences": {
            "human": {
                "commands": ["status", "plan", "apply", "verify", "revert", "cycle"],
                "default_output": "human",
                "safe_preview": "plan",
            },
            "automation": {
                "output": "json",
                "stable_schema": SCHEMA,
                "idempotence_signal": "changed",
                "success_signal": "passed",
            },
            "agent": {
                "discover": "contract",
                "observe": "status",
                "plan": "plan",
                "mutate": ["apply", "revert"],
                "verify": "verify",
                "preferred_output": "json",
            },
        },
        "desired": {
            "platform_tools_version": PLATFORM_TOOLS_VERSION,
            "managed_scope": "tool-owned root only",
            "host_os": ["Windows", "Linux", "Darwin"],
        },
    }

def _human(value: dict[str, Any]) -> str:
    op = value.get("operation")
    if op == "cycle":
        return f"qualification cycle: {'PASS' if value.get('passed') else 'FAIL'}"
    if op == "verify":
        return f"verify: {'PASS' if value.get('passed') else 'FAIL'} - {value.get('reason')}"
    if op == "apply":
        return f"apply: {'changed' if value.get('changed') else 'no change'}"
    if op == "revert":
        return f"revert: {'changed' if value.get('changed') else 'no change'}"
    if "action" in value:
        return f"plan: {value['action']} - {value.get('reason','')}"
    if "managed_adb_present" in value:
        return f"status: managed adb={'yes' if value['managed_adb_present'] else 'no'}, fastboot={'yes' if value['managed_fastboot_present'] else 'no'}"
    return json.dumps(value, indent=2, sort_keys=True)

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["status", "plan", "apply", "verify", "revert", "cycle", "contract"])
    ap.add_argument("--root", type=pathlib.Path, default=_default_root())
    ap.add_argument("--output", choices=["human", "json"], default="human")
    ap.add_argument("--allow-latest-fallback", action="store_true")
    args = ap.parse_args()
    if args.command == "status":
        value = asdict(observe(args.root))
    elif args.command == "plan":
        value = asdict(plan(args.root))
    elif args.command == "apply":
        value = apply(args.root, args.allow_latest_fallback)
    elif args.command == "verify":
        value = verify(args.root)
    elif args.command == "revert":
        value = revert(args.root)
    elif args.command == "cycle":
        value = cycle(args.root, args.allow_latest_fallback)
    else:
        value = contract()
    print(json.dumps(value, indent=2, sort_keys=True) if args.output == "json" else _human(value))
    if args.command in {"verify", "cycle"}:
        return 0 if value.get("passed") else 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
