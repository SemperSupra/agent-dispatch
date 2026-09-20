#!/usr/bin/env python3
"""Small oracle-backed primitive exercises for passively qualified GitHub runners."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_census as passive

PROBE_VERSION = "public-primitive/1"

def _run(argv: list[str], timeout: int = 15) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", str(exc)

def _cap(name: str, *, observed, installed, callable_, exercised, oracle,
         classification: str, reason: str, evidence=None) -> dict:
    return {
        "name": name,
        "advertised": None,
        "observed": observed,
        "installed": installed,
        "callable": callable_,
        "exercised": exercised,
        "oracleSatisfied": oracle,
        "classification": classification,
        "reason": reason,
        "evidence": evidence,
    }

def probe_kvm_api() -> dict:
    path = pathlib.Path("/dev/kvm")
    if platform.system() != "Linux":
        return _cap("linux:kvm-api", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="KVM probe is Linux-only")
    if not path.exists():
        return _cap("linux:kvm-api", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="/dev/kvm not present")
    try:
        import fcntl
        fd = os.open(str(path), os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        try:
            version = fcntl.ioctl(fd, 0xAE00, 0)  # KVM_GET_API_VERSION
        finally:
            os.close(fd)
    except Exception as exc:
        return _cap("linux:kvm-api", observed=True, installed=True, callable_=False,
                    exercised=True, oracle=False, classification="ORACLE_FAILURE",
                    reason=f"KVM_GET_API_VERSION failed: {type(exc).__name__}: {exc}")
    ok = version == 12
    return _cap("linux:kvm-api", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason=f"KVM_GET_API_VERSION returned {version}",
                evidence={"api_version": version})

def probe_docker_daemon() -> dict:
    docker = shutil.which("docker")
    if not docker:
        return _cap("docker:daemon-api", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="docker command not found")
    code, out, err = _run([docker, "version", "--format", "{{json .Server}}"], timeout=15)
    ok = code == 0 and bool(out) and out != "null"
    evidence = {"exit_code": code, "server_json": out[:2000] if out else None,
                "stderr": err[:1000] if err else None}
    return _cap("docker:daemon-api", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="Docker server API answered" if ok else "Docker CLI present but server API did not answer",
                evidence=evidence)

def probe_rosetta() -> dict:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        return _cap("macos:rosetta-exec", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Rosetta execution probe applies only to arm64 macOS")
    marker = pathlib.Path("/Library/Apple/usr/share/rosetta/rosetta")
    if not marker.exists():
        return _cap("macos:rosetta-exec", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="Rosetta marker not present")
    code, out, err = _run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"])
    ok = code == 0
    return _cap("macos:rosetta-exec", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="x86_64 /usr/bin/true executed under Rosetta" if ok else "Rosetta execution failed",
                evidence={"exit_code": code, "stderr": err[:1000] if err else None})

def probe_apple_toolchain() -> dict:
    if platform.system() != "Darwin":
        return _cap("macos:toolchain-query", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Apple toolchain probe is macOS-only")
    xcodebuild = shutil.which("xcodebuild")
    xcrun = shutil.which("xcrun")
    if not xcodebuild or not xcrun:
        return _cap("macos:toolchain-query", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="xcodebuild/xcrun not both present")
    xv, xout, xerr = _run([xcodebuild, "-version"])
    cv, cout, cerr = _run([xcrun, "--find", "clang"])
    sv, sout, serr = _run([xcrun, "simctl", "list", "runtimes", "-j"], timeout=20)
    runtimes = []
    if sv == 0 and sout:
        try:
            payload = json.loads(sout)
            for item in payload.get("runtimes", []):
                runtimes.append({
                    "name": item.get("name"),
                    "identifier": item.get("identifier"),
                    "version": item.get("version"),
                    "isAvailable": item.get("isAvailable"),
                })
        except json.JSONDecodeError:
            pass
    ok = xv == 0 and cv == 0 and sv == 0
    return _cap("macos:toolchain-query", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="Xcode, clang lookup, and Simulator runtime query succeeded" if ok
                       else "one or more Apple toolchain queries failed",
                evidence={
                    "xcode_version": xout[:1000] if xout else None,
                    "clang_path": cout[:1000] if cout else None,
                    "runtimes": runtimes,
                    "exit_codes": {"xcodebuild": xv, "xcrun_find": cv, "simctl": sv},
                    "stderr": {
                        "xcodebuild": xerr[:500] if xerr else None,
                        "xcrun_find": cerr[:500] if cerr else None,
                        "simctl": serr[:500] if serr else None,
                    },
                })


def probe_kvm_sudo_api() -> dict:
    path = pathlib.Path("/dev/kvm")
    if platform.system() != "Linux":
        return _cap("linux:kvm-api-sudo", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="privileged KVM control is Linux-only")
    if not path.exists():
        return _cap("linux:kvm-api-sudo", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="/dev/kvm not present")
    sudo = shutil.which("sudo")
    if not sudo:
        return _cap("linux:kvm-api-sudo", observed=True, installed=True, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="sudo command not present")
    snippet = (
        "import fcntl,os;"
        "fd=os.open('/dev/kvm',os.O_RDWR|getattr(os,'O_CLOEXEC',0));"
        "v=fcntl.ioctl(fd,0xAE00,0);os.close(fd);print(v)"
    )
    code, out, err = _run([sudo, "-n", sys.executable, "-c", snippet], timeout=15)
    ok = code == 0 and out.strip() == "12"
    return _cap("linux:kvm-api-sudo", observed=True, installed=True, callable_=ok,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="sudo KVM_GET_API_VERSION returned 12" if ok
                       else "passwordless sudo could not satisfy KVM API oracle",
                evidence={"exit_code": code, "api_version": out.strip() or None,
                          "stderr": err[:1000] if err else None})

def probe_docker_container() -> dict:
    docker = shutil.which("docker")
    if not docker:
        return _cap("docker:container-nonce", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="docker command not found")
    daemon_code, daemon_out, daemon_err = _run(
        [docker, "version", "--format", "{{json .Server}}"], timeout=15
    )
    if daemon_code != 0 or not daemon_out or daemon_out == "null":
        return _cap("docker:container-nonce", observed=True, installed=True, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Docker daemon oracle is not satisfied",
                    evidence={"exit_code": daemon_code,
                              "stderr": daemon_err[:1000] if daemon_err else None})
    import uuid
    nonce = uuid.uuid4().hex
    image = "busybox:1.37.0"
    pull_code, pull_out, pull_err = _run([docker, "pull", "--quiet", image], timeout=90)
    if pull_code != 0:
        return _cap("docker:container-nonce", observed=True, installed=True, callable_=True,
                    exercised=True, oracle=False, classification="ENVIRONMENT_FAILURE",
                    reason="bounded BusyBox image pull failed",
                    evidence={"image": image, "exit_code": pull_code,
                              "stderr": pull_err[:1000] if pull_err else None})
    import tempfile
    with tempfile.TemporaryDirectory(prefix="runner-census-docker-") as td:
        host = pathlib.Path(td)
        run_code, run_out, run_err = _run([
            docker, "run", "--rm", "--network", "none", "--read-only",
            "--mount", f"type=bind,src={host},dst=/work",
            "-e", f"CENSUS_NONCE={nonce}",
            image, "sh", "-c",
            "printf '%s' \"$CENSUS_NONCE\" > /work/nonce.txt && cat /work/nonce.txt",
        ], timeout=60)
        written = None
        nonce_path = host / "nonce.txt"
        if nonce_path.exists():
            written = nonce_path.read_text(errors="replace")
        ok = run_code == 0 and run_out.strip() == nonce and written == nonce
    inspect_code, digest, _ = _run(
        [docker, "image", "inspect", "--format", "{{join .RepoDigests \",\"}}", image],
        timeout=15,
    )
    _run([docker, "image", "rm", "--force", image], timeout=30)
    return _cap("docker:container-nonce", observed=True, installed=True, callable_=True,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="container executed isolated nonce + bind-mount round trip" if ok
                       else "container nonce/bind-mount oracle failed",
                evidence={"image": image, "image_digest": digest if inspect_code == 0 else None,
                          "exit_code": run_code,
                          "stdout_nonce_match": run_out.strip() == nonce,
                          "bind_nonce_match": written == nonce,
                          "stderr": run_err[:1000] if run_err else None})

def _version_key(value: str) -> tuple:
    parts = []
    for token in value.replace("-", ".").split("."):
        try:
            parts.append(int(token))
        except ValueError:
            parts.append(token)
    return tuple(parts)

def probe_simulator_boot() -> dict:
    if platform.system() != "Darwin":
        return _cap("macos:simulator-boot", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Simulator probe is macOS-only")
    xcrun = shutil.which("xcrun")
    if not xcrun:
        return _cap("macos:simulator-boot", observed=False, installed=False, callable_=False,
                    exercised=False, oracle=False, classification="NEGATIVE_OBSERVATION",
                    reason="xcrun not present")
    rc, runtimes_out, runtimes_err = _run([xcrun, "simctl", "list", "runtimes", "-j"], timeout=20)
    dc, devtypes_out, devtypes_err = _run([xcrun, "simctl", "list", "devicetypes", "-j"], timeout=20)
    if rc != 0 or dc != 0:
        return _cap("macos:simulator-boot", observed=True, installed=True, callable_=False,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="Simulator runtime/device-type query did not satisfy entry gate",
                    evidence={"runtime_exit": rc, "device_type_exit": dc,
                              "stderr": (runtimes_err + "\n" + devtypes_err)[:1000]})
    runtime_payload = json.loads(runtimes_out)
    devtype_payload = json.loads(devtypes_out)
    ios = [
        r for r in runtime_payload.get("runtimes", [])
        if r.get("isAvailable") and str(r.get("identifier", "")).startswith(
            "com.apple.CoreSimulator.SimRuntime.iOS-"
        )
    ]
    iphones = [
        d for d in devtype_payload.get("devicetypes", [])
        if str(d.get("identifier", "")).startswith(
            "com.apple.CoreSimulator.SimDeviceType.iPhone-"
        )
    ]
    if not ios or not iphones:
        return _cap("macos:simulator-boot", observed=True, installed=True, callable_=True,
                    exercised=False, oracle=False, classification="SKIPPED_GUARDRAIL",
                    reason="no available iOS runtime or iPhone device type")
    runtime = sorted(ios, key=lambda x: _version_key(str(x.get("version", "0"))))[-1]
    devtype = iphones[0]
    import uuid
    name = "RunnerCensus-" + uuid.uuid4().hex[:8]
    create_code, udid, create_err = _run([
        xcrun, "simctl", "create", name, devtype["identifier"], runtime["identifier"]
    ], timeout=30)
    udid = udid.strip()
    if create_code != 0 or not udid:
        return _cap("macos:simulator-boot", observed=True, installed=True, callable_=True,
                    exercised=True, oracle=False, classification="ORACLE_FAILURE",
                    reason="disposable Simulator device creation failed",
                    evidence={"runtime": runtime.get("identifier"),
                              "device_type": devtype.get("identifier"),
                              "exit_code": create_code,
                              "stderr": create_err[:1000] if create_err else None})
    boot_code = status_code = spawn_code = None
    status_out = spawn_out = boot_err = status_err = spawn_err = ""
    try:
        boot_code, _, boot_err = _run([xcrun, "simctl", "boot", udid], timeout=30)
        if boot_code == 0:
            status_code, status_out, status_err = _run(
                [xcrun, "simctl", "bootstatus", udid, "-b"], timeout=120
            )
        if boot_code == 0 and status_code == 0:
            spawn_code, spawn_out, spawn_err = _run(
                [xcrun, "simctl", "spawn", udid, "/usr/bin/uname", "-m"], timeout=30
            )
        ok = boot_code == 0 and status_code == 0 and spawn_code == 0 and bool(spawn_out.strip())
    finally:
        _run([xcrun, "simctl", "shutdown", udid], timeout=30)
        _run([xcrun, "simctl", "delete", udid], timeout=30)
    return _cap("macos:simulator-boot", observed=True, installed=True, callable_=True,
                exercised=True, oracle=ok,
                classification="SUPPORTED" if ok else "ORACLE_FAILURE",
                reason="disposable Simulator booted and executed guest uname" if ok
                       else "Simulator create/boot/guest-command oracle failed",
                evidence={"runtime": runtime.get("identifier"),
                          "runtime_version": runtime.get("version"),
                          "device_type": devtype.get("identifier"),
                          "boot_exit": boot_code, "bootstatus_exit": status_code,
                          "spawn_exit": spawn_code, "guest_arch": spawn_out.strip() or None,
                          "stderr": "\n".join(
                              x for x in (boot_err, status_err, spawn_err) if x
                          )[:1500] or None})

PROBES = {
    "kvm-api": probe_kvm_api,
    "docker-daemon": probe_docker_daemon,
    "rosetta": probe_rosetta,
    "apple-toolchain": probe_apple_toolchain,
    "kvm-sudo": probe_kvm_sudo_api,
    "docker-container": probe_docker_container,
    "simulator-boot": probe_simulator_boot,
}

def build_receipt(probe: str, label: str | None = None) -> dict:
    receipt = passive.build_receipt(label)
    receipt["provenance"]["probe_version"] = f"{PROBE_VERSION}:{probe}"
    receipt["capabilities"].append(PROBES[probe]())
    receipt["warnings"].append("primitive result proves only the named oracle; it does not imply workload qualification")
    return receipt

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", choices=sorted(PROBES), required=True)
    parser.add_argument("--label")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.probe, args.label)
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PRIMITIVE_RECEIPT={path}")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
