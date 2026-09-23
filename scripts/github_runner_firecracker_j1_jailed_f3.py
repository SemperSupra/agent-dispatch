#!/usr/bin/env python3
"""J1: exact F3 parity through the Firecracker jailer with matched timing."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_f3_useful_work as f3
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA = "firecracker-j1-jailed-f3-parity/v1"
AUTHORITY = "SemperSupra/agent-dispatch-private#287"
MANIFEST = pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")
KERNEL_MANIFEST = pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")


def _run(argv: list[str], timeout: int = 30) -> dict:
    code, out, err = f0._run(argv, timeout=timeout)
    return {"exit_code": code, "stdout": out or "", "stderr": err or "", "ok": code == 0}


def _find_binary(root: pathlib.Path, exact_name: str) -> pathlib.Path:
    found = [p for p in root.rglob(exact_name) if p.is_file()]
    if len(found) != 1:
        raise RuntimeError(f"expected one {exact_name}, found {len(found)}")
    return found[0]


def _sudo(argv: list[str], timeout: int = 30) -> dict:
    sudo = shutil.which("sudo")
    if not sudo:
        return {"ok": False, "exit_code": None, "stdout": "", "stderr": "sudo unavailable"}
    return _run([sudo, "-n", *argv], timeout=timeout)


def _create_ephemeral_identity(prefix: str) -> dict:
    group = f"{prefix}g"
    user = f"{prefix}u"
    groupadd = _sudo(["groupadd", "--system", group])
    if not groupadd["ok"]:
        raise RuntimeError(f"groupadd failed: {groupadd['stderr']}")
    useradd = _sudo([
        "useradd", "--system", "--no-create-home",
        "--shell", "/usr/sbin/nologin",
        "--gid", group, user,
    ])
    if not useradd["ok"]:
        _sudo(["groupdel", group])
        raise RuntimeError(f"useradd failed: {useradd['stderr']}")
    uid = int(_run(["id", "-u", user])["stdout"].strip())
    gid = int(_run(["id", "-g", user])["stdout"].strip())
    return {"user": user, "group": group, "uid": uid, "gid": gid}


def _delete_ephemeral_identity(identity: dict) -> dict:
    userdel = _sudo(["userdel", identity["user"]])
    groupdel = _sudo(["groupdel", identity["group"]])
    return {"userdel_ok": userdel["ok"], "groupdel_ok": groupdel["ok"]}


def _stage_trusted_runtime(
    base: pathlib.Path,
    firecracker: pathlib.Path,
    jailer: pathlib.Path,
) -> dict:
    bin_dir = base / "bin"
    jail_base = base / "jails"
    for cmd in [
        ["mkdir", "-p", str(bin_dir), str(jail_base)],
        ["cp", str(firecracker), str(bin_dir / firecracker.name)],
        ["cp", str(jailer), str(bin_dir / jailer.name)],
        ["chown", "-R", "root:root", str(base)],
        ["chmod", "0755", str(base), str(bin_dir), str(jail_base), str(bin_dir / firecracker.name), str(bin_dir / jailer.name)],
    ]:
        result = _sudo(cmd)
        if not result["ok"]:
            raise RuntimeError(f"trusted runtime staging failed: {cmd}: {result['stderr']}")
    return {
        "base": base,
        "bin_dir": bin_dir,
        "jail_base": jail_base,
        "firecracker": bin_dir / firecracker.name,
        "jailer": bin_dir / jailer.name,
    }


def _stage_jail_files(
    jail_root: pathlib.Path,
    kernel: pathlib.Path,
    initrd: pathlib.Path,
    config: dict,
    uid: int,
    gid: int,
) -> None:
    config_path = pathlib.Path(tempfile.mkstemp(prefix="j1-config-", suffix=".json")[1])
    try:
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
        for cmd in [
            ["mkdir", "-p", str(jail_root)],
            ["cp", str(kernel), str(jail_root / "vmlinux")],
            ["cp", str(initrd), str(jail_root / "initrd.cpio")],
            ["cp", str(config_path), str(jail_root / "vm-config.json")],
            ["chown", f"{uid}:{gid}", str(jail_root / "vmlinux"), str(jail_root / "initrd.cpio"), str(jail_root / "vm-config.json")],
            ["chmod", "0444", str(jail_root / "vmlinux"), str(jail_root / "initrd.cpio"), str(jail_root / "vm-config.json")],
        ]:
            result = _sudo(cmd)
            if not result["ok"]:
                raise RuntimeError(f"jail file staging failed: {cmd}: {result['stderr']}")
    finally:
        config_path.unlink(missing_ok=True)


def _process_observation(pid: int) -> dict:
    proc = pathlib.Path("/proc") / str(pid)
    result = {"pid": pid}
    status_result = _sudo(["cat", str(proc / "status")], timeout=5)
    if status_result["ok"]:
        for line in status_result["stdout"].splitlines():
            if line.startswith("Uid:"):
                result["uid_fields"] = [int(x) for x in line.split()[1:]]
            elif line.startswith("Gid:"):
                result["gid_fields"] = [int(x) for x in line.split()[1:]]
            elif line.startswith("NoNewPrivs:"):
                result["no_new_privs"] = int(line.split()[1])
            elif line.startswith("Seccomp:"):
                result["seccomp_mode"] = int(line.split()[1])
            elif line.startswith("NSpid:"):
                result["nspid"] = [int(x) for x in line.split()[1:]]
    else:
        result["status_error"] = status_result["stderr"] or "status read failed"
    for ns in ("mnt", "pid", "net", "user"):
        ns_result = _sudo(["readlink", str(proc / "ns" / ns)], timeout=5)
        result[f"{ns}_ns"] = ns_result["stdout"].strip() if ns_result["ok"] else None
    return result

def _find_process_by_real_uid(uid: int) -> dict | None:
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text()
            real_uid = None
            for line in status.splitlines():
                if line.startswith("Uid:"):
                    real_uid = int(line.split()[1])
                    break
            if real_uid == uid:
                return _process_observation(int(entry.name))
        except (OSError, ValueError):
            continue
    return None


def _run_jailed(
    jailer: pathlib.Path,
    firecracker: pathlib.Path,
    jail_base: pathlib.Path,
    vm_id: str,
    uid: int,
    gid: int,
    expected: dict,
) -> dict:
    sudo = shutil.which("sudo")
    if not sudo:
        return {"ok": False, "classification": "SETUP_REQUIRED", "reason": "sudo unavailable"}

    command = [
        sudo, "-n", str(jailer),
        "--id", vm_id,
        "--exec-file", str(firecracker),
        "--uid", str(uid),
        "--gid", str(gid),
        "--chroot-base-dir", str(jail_base),
        "--cgroup-version", "2",
        "--",
        "--no-api",
        "--config-file", "/vm-config.json",
    ]

    started = time.perf_counter()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pid_file = jail_base / firecracker.name / vm_id / "root" / f"{firecracker.name}.pid"
    observed = None
    deadline = time.time() + 10
    while time.time() < deadline and proc.poll() is None:
        candidate = _find_process_by_real_uid(uid)
        if candidate is None and pid_file.exists():
            try:
                candidate = _process_observation(int(pid_file.read_text().strip()))
            except (OSError, ValueError):
                candidate = None
        if candidate is not None:
            observed = candidate
            if candidate.get("seccomp_mode") == 2:
                break
        time.sleep(0.005)
    try:
        out, err = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    ended = time.perf_counter()
    combined = "\n".join(x for x in (out, err) if x)

    rm = f3.RESULT_RE.search(combined)
    em = f3.EXIT_RE.search(combined)
    im = f3.INIT_RE.search(combined)
    candidate = None
    if rm:
        candidate = {
            "bytes": int(rm.group(1)),
            "lines": int(rm.group(2)),
            "words": int(rm.group(3)),
            "fnv1a64": rm.group(4),
            "work_ns": int(rm.group(5)),
        }
    child = None
    if em:
        child = {"exit_code": int(em.group(1)), "elapsed_ns": int(em.group(2))}
    expected_match = bool(candidate) and all(candidate[k] == expected[k] for k in ("bytes", "lines", "words", "fnv1a64"))
    child_ok = bool(child) and child["exit_code"] == 0
    vmm_ok = proc.returncode == 0 and "Firecracker exiting successfully" in combined
    ok = expected_match and child_ok and vmm_ok

    return {
        "ok": ok,
        "classification": "SUPPORTED" if ok else "ORACLE_FAILURE",
        "reason": "jailed F3 guest matched unjailed useful-work oracle" if ok else "jailed F3 parity oracle failed",
        "elapsed_ms": round((ended - started) * 1000.0, 3),
        "return_code": proc.returncode,
        "candidate_result": candidate,
        "candidate_exit": child,
        "kernel_to_init_ms": float(im.group(1)) * 1000.0 if im else None,
        "process_observation": observed,
        "pid_file": str(pid_file),
        "output_tail": combined[-9000:],
        "command_shape": "sudo jailer --id ... --exec-file <trusted-firecracker> --uid ... --gid ... --chroot-base-dir <trusted> --cgroup-version 2 -- --no-api --config-file /vm-config.json",
    }


def run_probe(label: str) -> dict:
    timer = LifecycleTimer()
    vm = json.loads(MANIFEST.read_text())
    km = json.loads(KERNEL_MANIFEST.read_text())
    data = f3.DEFAULT_INPUT.read_bytes()
    expected = f3.expected_result(data)
    identity = None
    trusted = None

    with tempfile.TemporaryDirectory(prefix="firecracker-j1-") as td:
        work = pathlib.Path(td)
        archive = work / "firecracker.tgz"
        extract = work / "extract"; extract.mkdir()
        kernel = work / "vmlinux"
        init_bin = work / "init"
        cand_bin = work / "candidate"
        initrd = work / "initrd.cpio"
        unjailed_config_path = work / "unjailed-config.json"

        with timer.stage("vmm_download_and_verify", "venue"):
            vv = f1._download_and_verify(vm["archive_url"], vm["archive_sha256"], archive)
        with timer.stage("archive_extract", "portable"):
            f0._safe_extract(archive, extract)
            firecracker = _find_binary(extract, f"firecracker-{vm['version']}-{vm['architecture']}")
            jailer = _find_binary(extract, f"jailer-{vm['version']}-{vm['architecture']}")
            firecracker.chmod(firecracker.stat().st_mode | 0o111)
            jailer.chmod(jailer.stat().st_mode | 0o111)
        with timer.stage("kernel_download_and_verify", "venue"):
            kv = f1._download_and_verify(km["kernel_url"], km["kernel_sha256"], kernel)
        with timer.stage("candidate_compile", "portable"):
            cc = f1._compile_init(f3.CANDIDATE_SOURCE, cand_bin)
        with timer.stage("guest_init_compile", "portable"):
            ic = f1._compile_init(f3.INIT_SOURCE, init_bin)
        if not all([vv["verified"], kv["verified"], cc["ok"], ic["ok"]]):
            return {"schema": SCHEMA, "authority": AUTHORITY, "result": {"classification": "HARNESS_FAILURE"}}
        with timer.stage("capsule_initramfs_build", "portable"):
            f3.build_initramfs(init_bin, cand_bin, data, initrd)
        with timer.stage("unjailed_config_build", "portable"):
            f1._build_config(kernel, initrd, unjailed_config_path)

        unjailed_started = time.perf_counter()
        with timer.stage("unjailed_f3_lifecycle", "portable"):
            unjailed = f3.run_vm(firecracker, unjailed_config_path, expected)
        unjailed_elapsed_ms = round((time.perf_counter() - unjailed_started) * 1000.0, 3)
        if not unjailed.get("ok"):
            return {
                "schema": SCHEMA, "authority": AUTHORITY,
                "result": {"classification": "ORACLE_FAILURE", "reason": "matched unjailed baseline failed"},
                "unjailed": unjailed,
            }

        prefix = f"fcj1{os.getpid()}"
        with timer.stage("ephemeral_identity_create", "venue"):
            identity = _create_ephemeral_identity(prefix)

        trusted_base = pathlib.Path(f"/opt/agent-dispatch-fcj1-{os.getpid()}")
        try:
            with timer.stage("trusted_runtime_stage", "venue"):
                trusted = _stage_trusted_runtime(trusted_base, firecracker, jailer)

            vm_id = f"j1-{os.getpid()}"
            jail_root = trusted["jail_base"] / trusted["firecracker"].name / vm_id / "root"
            jailed_config = {
                "boot-source": {
                    "kernel_image_path": "/vmlinux",
                    "initrd_path": "/initrd.cpio",
                    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
                },
                "drives": [],
                "machine-config": {
                    "vcpu_count": 1,
                    "mem_size_mib": 128,
                    "smt": False,
                    "track_dirty_pages": False,
                    "huge_pages": "None",
                },
                "network-interfaces": [],
            }
            with timer.stage("jail_resource_stage", "venue"):
                _stage_jail_files(jail_root, kernel, initrd, jailed_config, identity["uid"], identity["gid"])

            with timer.stage("jailed_f3_lifecycle", "portable"):
                jailed = _run_jailed(
                    trusted["jailer"], trusted["firecracker"], trusted["jail_base"],
                    vm_id, identity["uid"], identity["gid"], expected,
                )
        finally:
            with timer.stage("jail_cleanup", "venue"):
                if trusted_base.exists():
                    _sudo(["rm", "-rf", str(trusted_base)])
            with timer.stage("ephemeral_identity_cleanup", "venue"):
                identity_cleanup = _delete_ephemeral_identity(identity) if identity else None

        unjailed_ms = unjailed_elapsed_ms
        jailed_ms = jailed.get("elapsed_ms")
        overhead_ms = round(jailed_ms - unjailed_ms, 3) if unjailed_ms is not None and jailed_ms is not None else None
        overhead_ratio = round(jailed_ms / unjailed_ms, 4) if unjailed_ms and jailed_ms is not None else None

        process = jailed.get("process_observation") or {}
        uid_ok = process.get("uid_fields") and process["uid_fields"][0] == identity["uid"]
        gid_ok = process.get("gid_fields") and process["gid_fields"][0] == identity["gid"]
        seccomp_ok = process.get("seccomp_mode") == 2
        parity_ok = bool(jailed.get("ok"))
        supported = parity_ok and bool(uid_ok) and bool(gid_ok) and bool(seccomp_ok)
        classification = "SUPPORTED" if supported else "INCONCLUSIVE" if parity_ok else "ORACLE_FAILURE"

        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "requested_label": label,
            "result": {
                "classification": classification,
                "jailed_f3_parity_satisfied": parity_ok,
                "uid_drop_observed": bool(uid_ok),
                "gid_drop_observed": bool(gid_ok),
                "seccomp_filter_mode_observed": bool(seccomp_ok),
            },
            "identity": identity,
            "identity_cleanup": identity_cleanup,
            "unjailed": {
                "elapsed_ms": unjailed_ms,
                "kernel_to_init_ms": unjailed.get("kernel_to_init_ms"),
                "candidate_result": unjailed.get("candidate_result"),
            },
            "jailed": jailed,
            "comparison": {
                "jailed_minus_unjailed_ms": overhead_ms,
                "jailed_over_unjailed_ratio": overhead_ratio,
            },
            "lifecycle_timing": timer.receipt(),
            "next_gate": "J2 one-at-a-time PID namespace/resource-limit/cgroup controls",
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args(); args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args.label)
    except Exception as exc:
        receipt = {
            "schema": SCHEMA, "authority": AUTHORITY,
            "result": {"classification": "HARNESS_FAILURE", "reason": f"{type(exc).__name__}: {exc}"},
        }
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["result"]["classification"] in {"SUPPORTED", "INCONCLUSIVE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
