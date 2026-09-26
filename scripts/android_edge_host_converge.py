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
import tempfile
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from typing import Any

PLATFORM_TOOLS_VERSION = "37.0.1"
SCHEMA = "android-edge-host-converger/v1"
PLATFORM_TOOLS_URLS = {
    "Windows": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
    "Linux": "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
    "Darwin": "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
}
GOOGLE_USB_DRIVER_URL = "https://dl.google.com/android/repository/usb_driver_r13-windows.zip"

# Populated only from independently observed successful qualification evidence.
# Once set, a mutable transport locator is rejected if its bytes drift.
EXPECTED_SHA256: dict[str, str] = {
    "Windows:platform-tools": "45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99",
    "Linux:platform-tools": "d230f13842f60f782a8645f9c813f8f845bf36089ea7289f28c48f17979313f1",
    "Darwin:platform-tools": "ee39ad5967e95c2a07f04dbcbde96b1a0c916ba376096db5d2f498b7727a5d1d",
    "Windows:google-usb-driver": "360b01d3dfb6c41621a3a64ae570dfac2c9a40cca1b5a1f136ae90d02f5e9e0b"
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
    windows_usb_driver_records: list[dict[str, str]]
    managed_windows_usb_driver_inf_present: bool
    hosted_ci: bool

@dataclass
class Plan:
    schema: str
    action: str
    changed: bool
    reason: str
    desired_version: str
    root: str
    managed_dir: str
    platform_tools_needed: bool
    windows_usb_driver_package_needed: bool
    windows_driver_store_needed: bool

def _default_root() -> pathlib.Path:
    system = platform.system()
    if system == "Windows":
        base = pathlib.Path(os.environ.get("LOCALAPPDATA") or pathlib.Path.home() / "AppData" / "Local")
        return base / "AndroidEdgeApplianceKit"
    return pathlib.Path.home() / ".local" / "share" / "android-edge-appliance-kit"

def _exe(name: str) -> str:
    return name + ".exe" if platform.system() == "Windows" else name

def _run(argv: list[str], timeout: int = 30) -> tuple[int | None, str, str]:
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
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Version "):
            return line.split()[1].split("-", 1)[0]
    return None

def _windows_driver_records() -> list[dict[str, str]]:
    """Cheap routine sensor: observe only Google Android USB Driver Store payloads."""
    if platform.system() != "Windows":
        return []
    windows = pathlib.Path(os.environ.get("WINDIR") or r"C:\\Windows")
    repository = windows / "System32" / "DriverStore" / "FileRepository"
    if not repository.is_dir():
        return []
    return [
        {"DriverStorePath": str(path)}
        for path in sorted(repository.glob("android_winusb.inf_*"))
        if path.is_dir()
    ]

def _windows_driver_package_records() -> list[dict[str, str]]:
    """Expensive identity sensor used only after mutation to capture oem*.inf."""
    if platform.system() != "Windows":
        return []
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        return []
    command = (
        "$ErrorActionPreference='Stop';"
        "$d=Get-WindowsDriver -Online -All | Where-Object {"
        "$_.OriginalFileName -and $_.OriginalFileName.ToLower().EndsWith('android_winusb.inf')"
        "} | Select-Object Driver,OriginalFileName,ProviderName;"
        "if ($null -eq $d) { '[]' } else { $d | ConvertTo-Json -Compress }"
    )
    code, out, _ = _run([shell, "-NoProfile", "-NonInteractive", "-Command", command], timeout=60)
    if code != 0 or not out:
        return []
    try:
        value = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(value, dict):
        value = [value]
    records: list[dict[str, str]] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                records.append({str(k): str(v) for k, v in item.items() if v is not None})
    return records
def _is_hosted_ci() -> bool:
    return os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

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
        windows_usb_driver_records=_windows_driver_records(),
        managed_windows_usb_driver_inf_present=(root / "usb_driver" / "android_winusb.inf").is_file(),
        hosted_ci=_is_hosted_ci(),
    )

def plan(root: pathlib.Path) -> Plan:
    obs = observe(root)
    tools_needed = not (
        obs.managed_adb_present
        and obs.managed_fastboot_present
        and obs.managed_adb_version == PLATFORM_TOOLS_VERSION
    )
    driver_package_needed = obs.system == "Windows" and not obs.managed_windows_usb_driver_inf_present
    driver_store_needed = (
        obs.system == "Windows"
        and not obs.hosted_ci
        and not bool(obs.windows_usb_driver_records)
    )
    changed = tools_needed or driver_package_needed or driver_store_needed or not obs.manifest_present
    reason_parts = []
    if tools_needed:
        reason_parts.append("managed platform-tools absent or not at desired version")
    if driver_package_needed:
        reason_parts.append("managed Google Android USB driver package absent")
    if driver_store_needed:
        reason_parts.append("Google Android USB Driver Store package absent")
    if not obs.manifest_present:
        reason_parts.append("managed manifest absent")
    return Plan(
        SCHEMA,
        "install-or-repair" if changed else "noop",
        changed,
        "; ".join(reason_parts) if reason_parts else "managed host environment already satisfies desired state",
        PLATFORM_TOOLS_VERSION,
        str(root),
        obs.managed_dir,
        tools_needed,
        driver_package_needed,
        driver_store_needed,
    )

def _download(url: str, dest: pathlib.Path, expected_sha256: str | None = None) -> str:
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as response, dest.open("wb") as f:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            f.write(chunk)
    digest = h.hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise RuntimeError(f"download SHA-256 mismatch for {url}: expected {expected_sha256}, got {digest}")
    return digest

def _install_platform_tools(root: pathlib.Path, temp_root: pathlib.Path) -> dict[str, str]:
    system = platform.system()
    if system not in PLATFORM_TOOLS_URLS:
        raise RuntimeError(f"unsupported operating system: {system}")
    url = PLATFORM_TOOLS_URLS[system]
    archive = temp_root / "platform-tools.zip"
    digest = _download(url, archive, EXPECTED_SHA256.get(f"{system}:platform-tools"))
    extract = temp_root / "platform-extract"
    extract.mkdir()
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(extract)
    staged = extract / "platform-tools"
    if system != "Windows":
        for executable in (staged / "adb", staged / "fastboot"):
            if executable.is_file():
                executable.chmod(executable.stat().st_mode | 0o111)
    if not (staged / _exe("adb")).is_file() or not (staged / _exe("fastboot")).is_file():
        raise RuntimeError("downloaded archive did not contain adb and fastboot")
    version = _adb_version(staged / _exe("adb"))
    if version != PLATFORM_TOOLS_VERSION:
        raise RuntimeError(
            f"downloaded adb version mismatch: expected {PLATFORM_TOOLS_VERSION!r}, got {version!r}"
        )
    managed = root / "platform-tools"
    previous = root / ".previous-platform-tools"
    if previous.exists():
        shutil.rmtree(previous)
    if managed.exists():
        managed.replace(previous)
    temp_target = root / ".platform-tools.new"
    if temp_target.exists():
        shutil.rmtree(temp_target)
    shutil.copytree(staged, temp_target)
    temp_target.replace(managed)
    return {"kind": "platform-tools", "url": url, "sha256": digest, "version": version}

def _install_windows_usb_driver(root: pathlib.Path, temp_root: pathlib.Path) -> dict[str, Any] | None:
    if platform.system() != "Windows":
        return None
    before_store = _windows_driver_records()
    driver_dir = root / "usb_driver"
    inf = driver_dir / "android_winusb.inf"
    digest = None
    url = GOOGLE_USB_DRIVER_URL
    package_changed = False
    if not inf.is_file():
        archive = temp_root / "google-usb-driver.zip"
        digest = _download(
            url,
            archive,
            EXPECTED_SHA256.get("Windows:google-usb-driver"),
        )
        extract = temp_root / "driver-extract"
        extract.mkdir()
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(extract)
        inf_candidates = list(extract.rglob("android_winusb.inf"))
        if len(inf_candidates) != 1:
            raise RuntimeError(f"expected one android_winusb.inf, found {len(inf_candidates)}")
        if driver_dir.exists():
            shutil.rmtree(driver_dir)
        shutil.copytree(inf_candidates[0].parent, driver_dir)
        package_changed = True
    if not inf.is_file():
        raise RuntimeError("managed Google Android USB driver package is incomplete")

    if _is_hosted_ci():
        return {
            "kind": "google-usb-driver",
            "changed": package_changed,
            "package_ready": True,
            "driver_store_mode": "stage-ok",
            "url": url,
            "sha256": digest,
            "owned_driver_names": [],
            "driver_store_before": before_store,
        }

    if before_store:
        return {
            "kind": "google-usb-driver",
            "changed": package_changed,
            "package_ready": True,
            "driver_store_mode": "preexisting",
            "url": url,
            "sha256": digest,
            "owned_driver_names": [],
            "driver_store_before": before_store,
        }

    pnputil = shutil.which("pnputil")
    if not pnputil:
        raise RuntimeError("pnputil is required to stage the Google Android USB driver on a physical Windows host")
    code, out, err = _run([pnputil, "/add-driver", str(inf)], timeout=90)
    after_store = _windows_driver_records()
    if code != 0 and not after_store:
        raise RuntimeError(f"pnputil driver staging failed ({code}): {out} {err}")
    if not after_store:
        raise RuntimeError("Google Android USB driver staging did not produce a Driver Store payload")
    after = _windows_driver_package_records()
    if not after:
        raise RuntimeError("Google Android USB driver payload is present but its published INF identity could not be resolved")
    owned = sorted(x.get("Driver") for x in after if x.get("Driver"))
    return {
        "kind": "google-usb-driver",
        "changed": True,
        "package_ready": True,
        "driver_store_mode": "owned",
        "staging_exit_code": code,
        "staging_stderr": err or None,
        "url": url,
        "sha256": digest,
        "owned_driver_names": owned,
        "records_after": after,
        "driver_store_after": after_store,
    }
def _read_manifest(root: pathlib.Path) -> dict[str, Any]:
    path = root / "manifest.json"
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}

def apply(root: pathlib.Path) -> dict[str, Any]:
    p = plan(root)
    if not p.changed:
        return {
            "schema": SCHEMA,
            "operation": "apply",
            "changed": False,
            "plan": asdict(p),
            "manifest": _read_manifest(root),
            "verification": verify(root),
        }
    root.mkdir(parents=True, exist_ok=True)
    downloads: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="android-edge-host-") as td:
        temp_root = pathlib.Path(td)
        if p.platform_tools_needed:
            downloads.append(_install_platform_tools(root, temp_root))
        driver_result = _install_windows_usb_driver(root, temp_root)
        if driver_result is not None:
            downloads.append(driver_result)
    prior = _read_manifest(root)
    manifest = {
        "schema": SCHEMA,
        "platform_tools_version": PLATFORM_TOOLS_VERSION,
        "system": platform.system(),
        "machine": platform.machine(),
        "components": downloads,
        "owned_windows_driver_names": next(
            (x.get("owned_driver_names", []) for x in downloads if x.get("kind") == "google-usb-driver"),
            prior.get("owned_windows_driver_names", []),
        ),
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verification = verify(root)
    if not verification["passed"]:
        raise RuntimeError("post-apply verification failed: " + verification["reason"])
    return {
        "schema": SCHEMA,
        "operation": "apply",
        "changed": True,
        "plan": asdict(p),
        "manifest": manifest,
        "verification": verification,
    }

def verify(root: pathlib.Path) -> dict[str, Any]:
    obs = observe(root)
    adb_ok = obs.managed_adb_present and obs.managed_adb_version == PLATFORM_TOOLS_VERSION
    fastboot_path = pathlib.Path(obs.managed_dir) / _exe("fastboot")
    fastboot_code, fastboot_out, fastboot_err = (
        _run([str(fastboot_path), "--version"]) if fastboot_path.is_file() else (None, "", "missing")
    )
    fastboot_ok = fastboot_path.is_file() and fastboot_code == 0 and PLATFORM_TOOLS_VERSION in fastboot_out
    driver_package_ok = obs.system != "Windows" or obs.managed_windows_usb_driver_inf_present
    driver_store_ok = (
        obs.system != "Windows"
        or obs.hosted_ci
        or bool(obs.windows_usb_driver_records)
    )
    passed = bool(adb_ok and fastboot_ok and driver_package_ok and driver_store_ok and obs.manifest_present)
    reason = (
        "managed adb/fastboot, manifest, and platform-specific host requirements satisfy desired state"
        if passed
        else "managed Android host environment does not satisfy desired state"
    )
    return {
        "schema": SCHEMA,
        "operation": "verify",
        "passed": passed,
        "reason": reason,
        "checks": {
            "adb": adb_ok,
            "fastboot": fastboot_ok,
            "windows_usb_driver_package": driver_package_ok,
            "windows_driver_store": driver_store_ok,
        },
        "observation": asdict(obs),
        "fastboot": {"exit_code": fastboot_code, "stdout": fastboot_out, "stderr": fastboot_err},
        "manifest": _read_manifest(root),
    }

def revert(root: pathlib.Path) -> dict[str, Any]:
    manifest = _read_manifest(root)
    errors: list[str] = []
    deleted_drivers: list[str] = []
    if platform.system() == "Windows":
        pnputil = shutil.which("pnputil")
        for name in manifest.get("owned_windows_driver_names", []):
            if not pnputil:
                errors.append(f"cannot remove owned driver {name}: pnputil unavailable")
                continue
            code, out, err = _run([pnputil, "/delete-driver", str(name), "/uninstall", "/force"], timeout=90)
            if code == 0:
                deleted_drivers.append(str(name))
            else:
                errors.append(f"failed to remove {name}: {out} {err}")
    changed = False
    for path in (root / "platform-tools", root / ".previous-platform-tools", root / "usb_driver"):
        if path.exists():
            shutil.rmtree(path)
            changed = True
    manifest_path = root / "manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()
        changed = True
    obs = observe(root)
    owned_names = set(manifest.get("owned_windows_driver_names", []))
    owned_still_present = bool(owned_names and obs.windows_usb_driver_records)
    passed = not errors and not owned_still_present and not obs.managed_adb_present and not obs.managed_fastboot_present
    return {
        "schema": SCHEMA,
        "operation": "revert",
        "changed": changed or bool(deleted_drivers),
        "passed": passed,
        "deleted_windows_drivers": deleted_drivers,
        "errors": errors,
        "observation": asdict(obs),
    }

def cycle(root: pathlib.Path) -> dict[str, Any]:
    before = asdict(observe(root))
    first_plan = asdict(plan(root))
    first_apply = apply(root)
    first_verify = verify(root)
    second_plan = asdict(plan(root))
    second_apply = apply(root)
    second_verify = verify(root)
    reverted = revert(root)
    after_revert = asdict(observe(root))
    reapplied = apply(root)
    final_verify = verify(root)
    passed = (
        first_verify["passed"]
        and second_plan["action"] == "noop"
        and second_apply["changed"] is False
        and second_verify["passed"]
        and reverted["passed"]
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
            "windows_google_usb_driver": "r13",
            "managed_scope": "tool-owned root plus an explicitly recorded Windows Driver Store package",
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
        return f"revert: {'PASS' if value.get('passed') else 'FAIL'}; {'changed' if value.get('changed') else 'no change'}"
    if "action" in value:
        return f"plan: {value['action']} - {value.get('reason','')}"
    if "managed_adb_present" in value:
        return (
            f"status: managed adb={'yes' if value['managed_adb_present'] else 'no'}, "
            f"fastboot={'yes' if value['managed_fastboot_present'] else 'no'}, "
            f"windows usb driver records={len(value.get('windows_usb_driver_records', []))}"
        )
    return json.dumps(value, indent=2, sort_keys=True)

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["status", "plan", "apply", "verify", "revert", "cycle", "contract"])
    ap.add_argument("--root", type=pathlib.Path, default=_default_root())
    ap.add_argument("--output", choices=["human", "json"], default="human")
    args = ap.parse_args()
    try:
        if args.command == "status":
            value = asdict(observe(args.root))
        elif args.command == "plan":
            value = asdict(plan(args.root))
        elif args.command == "apply":
            value = apply(args.root)
        elif args.command == "verify":
            value = verify(args.root)
        elif args.command == "revert":
            value = revert(args.root)
        elif args.command == "cycle":
            value = cycle(args.root)
        else:
            value = contract()
    except Exception as exc:
        value = {
            "schema": SCHEMA,
            "operation": args.command,
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(json.dumps(value, indent=2, sort_keys=True) if args.output == "json" else f"{args.command}: FAIL - {value['error']}")
        return 2
    print(json.dumps(value, indent=2, sort_keys=True) if args.output == "json" else _human(value))
    if args.command in {"verify", "cycle", "revert"}:
        return 0 if value.get("passed") else 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
