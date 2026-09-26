#!/usr/bin/env python3
"""One-off public-safe probe: can hosted macOS ARM boot the AAR Play AVD with acceleration disabled?"""
from __future__ import annotations
import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys
import time
from typing import Any

def load_host(aar: pathlib.Path):
    path = aar / "tools" / "aar_play_host.py"
    spec = importlib.util.spec_from_file_location("aar_play_host_probe", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load AAR host tool")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def invoke(tool: pathlib.Path, state: pathlib.Path, args: list[str]) -> tuple[int, dict[str, Any], str]:
    cp = subprocess.run(
        [sys.executable, str(tool), "--state-root", str(state), "--format", "json", *args],
        text=True, capture_output=True, encoding="utf-8", errors="replace"
    )
    payload = {}
    if cp.stdout.strip():
        try:
            payload = json.loads(cp.stdout)
        except json.JSONDecodeError:
            payload = {}
    return cp.returncode, payload, (cp.stderr or "")[-4000:]

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--aar-root", type=pathlib.Path, required=True)
    p.add_argument("--out", type=pathlib.Path, required=True)
    p.add_argument("--boot-timeout", type=int, default=900)
    args = p.parse_args()

    aar = args.aar_root.resolve()
    host = load_host(aar)
    tool = aar / "tools" / "aar_play_host.py"
    state = aar / ".local" / "gha-arm-software-probe"
    result: dict[str, Any] = {
        "schema": "agent-dispatch-aar-macos-arm-software-probe/v1",
        "classification": "INCONCLUSIVE",
        "passed": False,
        "stages": [],
    }

    def stage(name: str, argv: list[str]):
        rc, receipt, stderr = invoke(tool, state, argv)
        result["stages"].append({"name": name, "exit_code": rc, "receipt": receipt, "stderr_tail": stderr or None})
        return rc, receipt

    observe_rc, observe = stage("observe", ["observe"])
    if observe_rc != 0:
        result["classification"] = "OBSERVE_FAILED"
        final = 1
    else:
        plan_rc, plan = stage("plan", ["plan", "--accept-sdk-licenses"])
        if plan_rc != 0:
            result["classification"] = "PLAN_FAILED"
            final = 1
        else:
            plan_path = pathlib.Path(plan["evidence"]["plan"])
            apply_rc, apply_receipt = stage("apply", ["apply", "--plan", str(plan_path)])
            if apply_rc != 0:
                result["classification"] = "APPLY_FAILED"
                final = 1
            else:
                plan_data = host.read_json(plan_path)
                runtime = pathlib.Path(plan_data["runtime_root"])
                profile = plan_data["profile"]
                env = host.process_env(runtime, profile)
                sdk = runtime / "sdk"
                emulator = sdk / "emulator" / host.executable("emulator", profile["os"])
                adb = sdk / "platform-tools" / host.executable("adb", profile["os"])
                log_path = runtime / "emulator-software-probe.log"
                adb_start = host.run([str(adb), "start-server"], env=env, timeout=30, check=False)
                if adb_start.returncode != 0:
                    result["classification"] = "ADB_START_FAILED"
                    final = 1
                else:
                    command = [
                        str(emulator), "-avd", plan_data["avd_name"],
                        "-no-window", "-no-audio", "-no-boot-anim",
                        "-no-snapshot-load", "-no-snapshot-save",
                        "-accel", "off", "-gpu", "swiftshader_indirect", "-no-metrics",
                    ]
                    proc = None
                    log = log_path.open("w", encoding="utf-8")
                    serial = None
                    booted = False
                    states: list[dict[str, str]] = []
                    started = time.monotonic()
                    try:
                        proc = subprocess.Popen(
                            command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
                        )
                        deadline = started + args.boot_timeout
                        while time.monotonic() < deadline and proc.poll() is None:
                            devices = host.parse_adb_devices(
                                host.run([str(adb), "devices"], env=env, timeout=15, check=False).stdout
                            )
                            if devices:
                                serial = serial or next(iter(devices))
                                snap = {"serial": serial, "state": devices.get(serial, "unknown")}
                                if not states or states[-1] != snap:
                                    states.append(snap)
                            if serial and devices.get(serial) == "device":
                                boot = host.run(
                                    [str(adb), "-s", serial, "shell", "getprop", "sys.boot_completed"],
                                    env=env, timeout=15, check=False
                                )
                                if boot.returncode == 0 and boot.stdout.strip() == "1":
                                    booted = True
                                    break
                            time.sleep(5)
                        log.flush()
                        evidence: dict[str, Any] = {
                            "command": command,
                            "elapsed_seconds": round(time.monotonic() - started, 3),
                            "emulator_exit_code": proc.poll() if proc else None,
                            "serial": serial,
                            "adb_states": states,
                            "emulator_log_tail": host.text_tail(log_path, 12000),
                            "toolchain_identity": apply_receipt.get("evidence", {}).get("toolchain_identity"),
                        }
                        if booted and serial:
                            play = host.run([str(adb), "-s", serial, "shell", "pm", "path", "com.android.vending"], env=env, timeout=30, check=False)
                            api = host.run([str(adb), "-s", serial, "shell", "getprop", "ro.build.version.sdk"], env=env, timeout=15, check=False).stdout.strip()
                            abi = host.run([str(adb), "-s", serial, "shell", "getprop", "ro.product.cpu.abi"], env=env, timeout=15, check=False).stdout.strip()
                            evidence.update({"boot_completed": True, "play_store_present": "package:" in play.stdout, "api_level": api, "abi": abi})
                            result["passed"] = bool("package:" in play.stdout and api == "35" and abi == "arm64-v8a")
                            result["classification"] = "SOFTWARE_AVD_LIVE_READY" if result["passed"] else "GUEST_IDENTITY_FAILED"
                            final = 0 if result["passed"] else 1
                        else:
                            result["classification"] = "SOFTWARE_AVD_UNAVAILABLE"
                            final = 1
                        result["software_probe"] = evidence
                    finally:
                        if proc is not None:
                            host.stop_emulator_process(proc, serial=serial, adb=adb, env=env, os_name="macos")
                        log.close()
                        host.run([str(adb), "kill-server"], env=env, timeout=20, check=False)
                    cleanup_rc, cleanup = stage("cleanup", ["cleanup", "--plan", str(plan_path)])
                    result["cleanup_passed"] = cleanup_rc == 0 and cleanup.get("status") == "cleaned"
                    if not result["cleanup_passed"]:
                        result["passed"] = False
                        result["classification"] = "CLEANUP_FAILED"
                        final = 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return final

if __name__ == "__main__":
    raise SystemExit(main())
