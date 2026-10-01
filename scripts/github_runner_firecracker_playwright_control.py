#!/usr/bin/env python3
"""P0a: networkless Playwright control inside a jailed Firecracker guest.

This is deliberately a workload-specific proving rep, not a generic microVM
runner. The Playwright userspace is derived from the official pinned-version
container, executed as an unprivileged guest user with chromiumSandbox=true,
and independently validated from the writable scratch image after guest exit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import firecracker_workload_evidence as evidence
import firecracker_execution_adapter as exec_adapter
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import github_runner_firecracker_j1_jailed_f3 as j1
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA = "firecracker-playwright-control/v1"
AUTHORITY = "SemperSupra/agent-dispatch-private#415"
ASSIGNMENT = "firecracker-real-workload-placement/playwright-p0a"
ASSIGNMENT_REVISION = "p0a-v1"
PLAYWRIGHT_VERSION = "1.63.0"
BASE_IMAGE_TAG = f"mcr.microsoft.com/playwright:v{PLAYWRIGHT_VERSION}-noble"
PLAYWRIGHT_RELEASE = "https://github.com/microsoft/playwright/releases/tag/v1.63.0"
INIT_SOURCE = pathlib.Path("experiments/firecracker/guest/playwright-control-init-x86_64.c")
CONTROL_JS = pathlib.Path("experiments/firecracker/guest/playwright-control.js")
CONTROL_HTML = pathlib.Path("experiments/firecracker/guest/playwright-control.html")
KERNEL_MANIFEST = pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")
VMM_MANIFEST = pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")
CONTROL_RE = re.compile(
    r"FIRECRACKER_PLAYWRIGHT_CONTROL ok=(\d+) sandbox=(\d+) network=(\d+)(?: browser=(\S+))?"
)
EXIT_RE = re.compile(r"FIRECRACKER_PLAYWRIGHT_EXIT code=(\d+)")


class ProbeError(RuntimeError):
    def __init__(self, classification: str, reason: str):
        super().__init__(reason)
        self.classification = classification
        self.reason = reason


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(argv: list[str], timeout: int = 60, cwd: pathlib.Path | None = None) -> dict:
    cp = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "ok": cp.returncode == 0,
        "exit_code": cp.returncode,
        "stdout": cp.stdout or "",
        "stderr": cp.stderr or "",
    }


def _required_tools() -> dict:
    names = (
        "docker", "mksquashfs", "tar", "truncate", "mkfs.ext4",
        "debugfs", "gcc", "sudo",
    )
    return {name: shutil.which(name) for name in names}


def _docker_repo_digest(tag: str) -> str | None:
    result = _run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", tag], timeout=20)
    if not result["ok"]:
        return None
    try:
        values = json.loads(result["stdout"].strip())
    except Exception:
        return None
    for value in values or []:
        if value.startswith("mcr.microsoft.com/playwright@sha256:"):
            return value
    return values[0] if values else None


def _build_playwright_rootfs(work: pathlib.Path, timer: LifecycleTimer) -> dict:
    image_tag = f"agent-dispatch-playwright-p0a:{os.getpid()}"
    container_id = None
    root_dir = work / "rootfs-dir"
    rootfs = work / "playwright-root.squashfs"
    root_dir.mkdir()
    primary_exc: Exception | None = None
    result: dict | None = None
    container_removed = True

    try:
        with timer.stage("playwright_base_pull", "venue"):
            pull = _run(["docker", "pull", BASE_IMAGE_TAG], timeout=600)
        if not pull["ok"]:
            raise ProbeError("SETUP_REQUIRED", "Playwright base image pull failed: " + (pull["stderr"] or pull["stdout"])[-2000:])

        base_digest = _docker_repo_digest(BASE_IMAGE_TAG)
        if not base_digest:
            raise ProbeError("HARNESS_FAILURE", "could not resolve pulled Playwright image digest")

        dockerfile = work / "Dockerfile"
        dockerfile.write_text(
            "FROM " + base_digest + "\n"
            "RUN mkdir -p /opt/pw && cd /opt/pw && npm init -y >/dev/null 2>&1 "
            f"&& npm install --omit=dev playwright@{PLAYWRIGHT_VERSION}\n"
            "RUN getent group 20001 >/dev/null || groupadd -g 20001 pwguest; "
            "id -u pwguest >/dev/null 2>&1 || useradd -m -u 20001 -g 20001 -s /bin/bash pwguest\n"
            "RUN test -x /usr/bin/node && test -d /ms-playwright && "
            "node -e \"const p=require('/opt/pw/node_modules/playwright/package.json');"
            f"if(p.version!=='{PLAYWRIGHT_VERSION}')process.exit(17)\"\n"
        )

        with timer.stage("playwright_userspace_build", "venue"):
            build = _run(
                ["docker", "build", "--pull=false", "-t", image_tag, "-f", str(dockerfile), str(work)],
                timeout=600,
            )
        if not build["ok"]:
            raise ProbeError("HARNESS_FAILURE", "Playwright userspace image build failed: " + (build["stderr"] or build["stdout"])[-3000:])

        verify = _run([
            "docker", "run", "--rm", image_tag,
            "node", "-e",
            "const p=require('/opt/pw/node_modules/playwright/package.json');"
            "console.log(JSON.stringify({version:p.version,node:process.version}));",
        ], timeout=30)
        if not verify["ok"]:
            raise ProbeError("HARNESS_FAILURE", "Playwright image verification failed: " + (verify["stderr"] or verify["stdout"])[-2000:])
        try:
            tool_identity = json.loads(verify["stdout"].strip().splitlines()[-1])
        except Exception as exc:
            raise ProbeError("HARNESS_FAILURE", f"tool identity parse failed: {exc}") from exc

        create = _run(["docker", "create", image_tag, "/bin/true"], timeout=30)
        if not create["ok"]:
            raise ProbeError("HARNESS_FAILURE", "docker create failed: " + (create["stderr"] or create["stdout"])[-2000:])
        container_id = create["stdout"].strip()

        with timer.stage("playwright_rootfs_export_extract", "venue"):
            extract = _run([
                "bash", "-o", "pipefail", "-c",
                'docker export "$1" | sudo -n tar --numeric-owner --same-owner -xpf - -C "$2"',
                "p0a-export", container_id, str(root_dir),
            ], timeout=600)
        if not extract["ok"]:
            raise ProbeError(
                "SETUP_REQUIRED",
                "streamed docker export/rootfs extraction failed: "
                + (extract["stderr"] or extract["stdout"])[-3000:],
            )

        with timer.stage("playwright_rootfs_squashfs", "portable"):
            squash = _run([
                "sudo", "-n", "mksquashfs", str(root_dir), str(rootfs),
                "-noappend", "-comp", "gzip", "-quiet",
            ], timeout=600)
        if not squash["ok"]:
            raise ProbeError("HARNESS_FAILURE", "mksquashfs failed: " + (squash["stderr"] or squash["stdout"])[-3000:])

        own = _run(["sudo", "-n", "chown", f"{os.getuid()}:{os.getgid()}", str(rootfs)], timeout=20)
        if not own["ok"]:
            raise ProbeError("SETUP_REQUIRED", "could not return rootfs ownership: " + (own["stderr"] or own["stdout"])[-1000:])

        result = {
            "ok": True,
            "rootfs": rootfs,
            "base_image_tag": BASE_IMAGE_TAG,
            "base_image_digest": base_digest,
            "tool_identity": tool_identity,
            "rootfs_sha256": _sha256(rootfs),
            "rootfs_size_bytes": rootfs.stat().st_size,
        }
    except Exception as exc:
        primary_exc = exc

    if container_id:
        container_cleanup = _run(["docker", "rm", "-f", container_id], timeout=30)
        container_removed = container_cleanup["ok"]
    _run(["docker", "rmi", "-f", image_tag], timeout=60)

    root_cleanup = {"ok": True, "stderr": "", "stdout": ""}
    if root_dir.exists():
        root_cleanup = _run(["sudo", "-n", "rm", "-rf", str(root_dir)], timeout=120)
    cleanup_ok = container_removed and root_cleanup["ok"]

    if primary_exc is not None:
        if not cleanup_ok and isinstance(primary_exc, ProbeError):
            extra = (root_cleanup["stderr"] or root_cleanup["stdout"] or "container cleanup failed")[-1000:]
            primary_exc.reason += f"; staging cleanup also failed: {extra}"
            primary_exc.args = (primary_exc.reason,)
        raise primary_exc

    if not cleanup_ok:
        detail = (root_cleanup["stderr"] or root_cleanup["stdout"] or "container cleanup failed")[-1000:]
        raise ProbeError("CLEANUP_FAILURE", "Playwright rootfs staging cleanup failed: " + detail)

    assert result is not None
    result["staging_cleanup"] = {
        "container_removed": container_removed,
        "root_dir_removed": not root_dir.exists(),
    }
    return result

def _make_scratch(path: pathlib.Path) -> dict:
    truncate = _run(["truncate", "-s", "1G", str(path)], timeout=20)
    if not truncate["ok"]:
        return truncate
    mkfs = _run(["mkfs.ext4", "-q", "-F", str(path)], timeout=60)
    return mkfs


def _build_initramfs(init_bin: pathlib.Path, output: pathlib.Path) -> None:
    import stat
    payload = b"".join([
        f1._newc_entry(".", mode=stat.S_IFDIR | 0o755, ino=1, nlink=2),
        f1._newc_entry("dev", mode=stat.S_IFDIR | 0o755, ino=2, nlink=2),
        f1._newc_entry("dev/console", mode=stat.S_IFCHR | 0o600, ino=3, rdevmajor=5, rdevminor=1),
        f1._newc_entry("dev/vda", mode=stat.S_IFBLK | 0o660, ino=4, rdevmajor=254, rdevminor=0),
        f1._newc_entry("dev/vdb", mode=stat.S_IFBLK | 0o660, ino=5, rdevmajor=254, rdevminor=16),
        f1._newc_entry("newroot", mode=stat.S_IFDIR | 0o755, ino=6, nlink=2),
        f1._newc_entry("work", mode=stat.S_IFDIR | 0o555, ino=7, nlink=2),
        f1._newc_entry("work/control.js", mode=stat.S_IFREG | 0o444, data=CONTROL_JS.read_bytes(), ino=8),
        f1._newc_entry("work/control.html", mode=stat.S_IFREG | 0o444, data=CONTROL_HTML.read_bytes(), ino=9),
        f1._newc_entry("init", mode=stat.S_IFREG | 0o755, data=init_bin.read_bytes(), ino=10),
        f1._newc_entry("TRAILER!!!", mode=0, ino=11),
    ])
    output.write_bytes(payload)


def _stage_file(src: pathlib.Path, dst: pathlib.Path, uid: int, gid: int, mode: str, sparse: bool = False) -> None:
    cp = ["cp"]
    if sparse:
        cp.append("--sparse=always")
    cp.extend([str(src), str(dst)])
    for argv in (
        ["mkdir", "-p", str(dst.parent)],
        cp,
        ["chown", f"{uid}:{gid}", str(dst)],
        ["chmod", mode, str(dst)],
    ):
        rr = j1._sudo(argv, timeout=120)
        if not rr["ok"]:
            raise RuntimeError(f"stage failed {argv}: {rr['stderr']}")


def _stage_vm(jail_root: pathlib.Path, *, kernel: pathlib.Path, initrd: pathlib.Path,
              rootfs: pathlib.Path, scratch: pathlib.Path, config: pathlib.Path,
              uid: int, gid: int) -> None:
    for src, dst, mode, sparse in (
        (kernel, jail_root / "vmlinux", "0444", False),
        (initrd, jail_root / "initrd.cpio", "0444", False),
        (rootfs, jail_root / "playwright.squashfs", "0444", True),
        (scratch, jail_root / "scratch.ext4", "0660", True),
        (config, jail_root / "vm-config.json", "0444", False),
    ):
        _stage_file(src, dst, uid, gid, mode, sparse)


def _run_jailed(*, jailer: pathlib.Path, firecracker: pathlib.Path, jail_base: pathlib.Path,
                vm_id: str, uid: int, gid: int) -> dict:
    command = [
        "sudo", "-n", str(jailer),
        "--id", vm_id,
        "--exec-file", str(firecracker),
        "--uid", str(uid), "--gid", str(gid),
        "--chroot-base-dir", str(jail_base),
        "--cgroup-version", "2",
        "--new-pid-ns",
        "--resource-limit", "no-file=4096",
        "--resource-limit", "fsize=2147483648",
        "--", "--no-api", "--config-file", "/vm-config.json",
    ]
    host_ns = {ns: os.readlink(f"/proc/self/ns/{ns}") for ns in ("mnt", "pid")}
    started = time.perf_counter()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pid_file = jail_base / firecracker.name / vm_id / "root" / f"{firecracker.name}.pid"
    observation = None
    deadline = time.time() + 20
    while time.time() < deadline:
        if pid_file.exists():
            rr = j1._sudo(["cat", str(pid_file)], timeout=5)
            if rr["ok"]:
                try:
                    observation = j1._process_observation(int(rr["stdout"].strip()))
                except Exception:
                    observation = None
        if observation is None:
            observation = j1._find_process_by_real_uid(uid)
        if observation and observation.get("seccomp_mode") == 2:
            break
        if proc.poll() is not None:
            break
        time.sleep(0.01)

    try:
        out, err = proc.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()

    combined = "\n".join(x for x in (out, err) if x)
    control = CONTROL_RE.search(combined)
    exitm = EXIT_RE.search(combined)
    guest_exit = int(exitm.group(1)) if exitm else None
    guest_ok = bool(control) and control.group(1) == "1" and control.group(2) == "1" and control.group(3) == "0" and guest_exit == 0
    uid_ok = bool(observation and observation.get("uid_fields") and observation["uid_fields"][0] == uid)
    gid_ok = bool(observation and observation.get("gid_fields") and observation["gid_fields"][0] == gid)
    seccomp_ok = bool(observation and observation.get("seccomp_mode") == 2)
    pidns_ok = bool(observation and observation.get("pid_ns") not in {None, host_ns["pid"]})
    mntns_ok = bool(observation and observation.get("mnt_ns") not in {None, host_ns["mnt"]})
    clean = proc.returncode == 0 and "Firecracker exiting successfully" in combined
    ok = guest_ok and uid_ok and gid_ok and seccomp_ok and pidns_ok and mntns_ok and clean
    return {
        "ok": ok,
        "classification": "SUPPORTED" if ok else "WORKLOAD_FAILURE",
        "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "return_code": proc.returncode,
        "guest_exit_code": guest_exit,
        "guest_oracle_observed": guest_ok,
        "browser_version": control.group(4) if control and control.group(4) else None,
        "jailer_uid_drop_observed": uid_ok,
        "jailer_gid_drop_observed": gid_ok,
        "jailer_seccomp_observed": seccomp_ok,
        "jailer_pid_namespace_observed": pidns_ok,
        "jailer_mount_namespace_observed": mntns_ok,
        "clean_vmm_exit_observed": clean,
        "process_observation": observation,
        "output_tail": combined[-16000:],
    }


def _export_scratch(jail_path: pathlib.Path, destination: pathlib.Path) -> None:
    for argv in (
        ["cp", "--sparse=always", str(jail_path), str(destination)],
        ["chown", f"{os.getuid()}:{os.getgid()}", str(destination)],
        ["chmod", "0600", str(destination)],
    ):
        rr = j1._sudo(argv, timeout=120)
        if not rr["ok"]:
            raise RuntimeError(f"scratch export failed: {argv}: {rr['stderr']}")


def _inspect_outputs(scratch: pathlib.Path, work: pathlib.Path) -> dict:
    result_path = work / "playwright-result.json"
    screenshot_path = work / "playwright-control.png"
    for guest, host in (
        ("/playwright-result.json", result_path),
        ("/playwright-control.png", screenshot_path),
    ):
        rr = _run(["debugfs", "-R", f"dump -p {guest} {host}", str(scratch)], timeout=30)
        if not rr["ok"] or not host.exists():
            return {"ok": False, "reason": f"could not extract {guest}", "detail": rr}
    try:
        result = json.loads(result_path.read_text())
    except Exception as exc:
        return {"ok": False, "reason": f"invalid result JSON: {exc}"}
    expected = (
        result.get("ok") is True
        and result.get("sandbox_requested") is True
        and result.get("network_used") is False
        and result.get("title") == "Firecracker Playwright Control"
        and result.get("dom_result") == "firecracker-playwright-ok:42"
        and result.get("ready") == "1"
        and result.get("screenshot_exists") is True
        and screenshot_path.stat().st_size > 100
    )
    return {
        "ok": expected,
        "result": result,
        "result_sha256": _sha256(result_path),
        "screenshot_sha256": _sha256(screenshot_path),
        "screenshot_size_bytes": screenshot_path.stat().st_size,
    }


def run_probe(label: str) -> dict:
    timer = LifecycleTimer()
    vm = json.loads(VMM_MANIFEST.read_text())
    km = json.loads(KERNEL_MANIFEST.read_text())
    tools = _required_tools()

    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise ProbeError("VENUE_LIMITATION", "P0a requires x86_64 Linux")
    missing = [name for name, path in tools.items() if not path]
    if missing:
        raise ProbeError("SETUP_REQUIRED", f"required host tools unavailable: {missing}")

    kvm_access = exec_adapter.select_kvm_access()
    if kvm_access.get("classification") != "SUPPORTED":
        raise ProbeError(
            "VENUE_LIMITATION",
            "callable KVM is required for P0a; observed "
            + json.dumps({
                "mode": kvm_access.get("mode"),
                "user_probe": kvm_access.get("user_probe"),
                "sudo_probe": kvm_access.get("sudo_probe"),
            }, sort_keys=True),
        )

    trusted_base = pathlib.Path(f"/opt/agent-dispatch-fcpw-{os.getpid()}")
    identity = None
    runtime = None
    cleanup = {"ok": False}
    execution = {"classification": "INCONCLUSIVE"}
    outputs = {}
    rootfs_info = {}
    root_immutable = False

    with tempfile.TemporaryDirectory(prefix="firecracker-playwright-") as td:
        work = pathlib.Path(td)
        archive = work / "firecracker.tgz"
        extract = work / "extract"
        extract.mkdir()
        kernel = work / "vmlinux"
        init_bin = work / "init"
        initrd = work / "initrd.cpio"
        scratch = work / "scratch.ext4"
        config = work / "vm.json"
        exported_scratch = work / "scratch-after.ext4"

        try:
            with timer.stage("vmm_download_and_verify", "venue"):
                vv = f1._download_and_verify(vm["archive_url"], vm["archive_sha256"], archive)
            with timer.stage("vmm_extract", "portable"):
                f0._safe_extract(archive, extract)
                firecracker = j1._find_binary(extract, f"firecracker-{vm['version']}-{vm['architecture']}")
                jailer = j1._find_binary(extract, f"jailer-{vm['version']}-{vm['architecture']}")
                firecracker.chmod(firecracker.stat().st_mode | 0o111)
                jailer.chmod(jailer.stat().st_mode | 0o111)
            with timer.stage("kernel_download_and_verify", "venue"):
                kv = f1._download_and_verify(km["kernel_url"], km["kernel_sha256"], kernel)
            with timer.stage("bridge_init_compile", "portable"):
                ic = f1._compile_init(INIT_SOURCE, init_bin)
            if not (vv["verified"] and kv["verified"] and ic["ok"]):
                raise ProbeError("HARNESS_FAILURE", "pinned VMM/kernel/init preparation failed")

            rootfs_info = _build_playwright_rootfs(work, timer)
            if not rootfs_info.get("ok"):
                raise ProbeError(
                    rootfs_info.get("classification", "HARNESS_FAILURE"),
                    rootfs_info.get("reason", "Playwright rootfs materialization failed"),
                )
            rootfs = rootfs_info["rootfs"]
            root_before = _sha256(rootfs)

            with timer.stage("initramfs_build", "portable"):
                _build_initramfs(init_bin, initrd)
            with timer.stage("scratch_create", "venue"):
                ss = _make_scratch(scratch)
            if not ss["ok"]:
                raise ProbeError("SETUP_REQUIRED", f"scratch creation failed: {ss['stderr']}")

            identity = j1._create_ephemeral_identity(f"fcpw{os.getpid()}")
            runtime = j1._stage_trusted_runtime(trusted_base, firecracker, jailer)
            vm_id = f"pw{os.getpid()}"

            cfg = f1._build_config(kernel, initrd, config)
            cfg["boot-source"]["kernel_image_path"] = "/vmlinux"
            cfg["boot-source"]["initrd_path"] = "/initrd.cpio"
            cfg["machine-config"]["vcpu_count"] = 2
            cfg["machine-config"]["mem_size_mib"] = 2048
            cfg["drives"] = [
                {
                    "drive_id": "userspace",
                    "path_on_host": "/playwright.squashfs",
                    "is_root_device": False,
                    "is_read_only": True,
                },
                {
                    "drive_id": "scratch",
                    "path_on_host": "/scratch.ext4",
                    "is_root_device": False,
                    "is_read_only": False,
                },
            ]
            cfg["network-interfaces"] = []
            config.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n")

            jail_root = runtime["jail_base"] / runtime["firecracker"].name / vm_id / "root"
            _stage_vm(
                jail_root,
                kernel=kernel,
                initrd=initrd,
                rootfs=rootfs,
                scratch=scratch,
                config=config,
                uid=identity["uid"],
                gid=identity["gid"],
            )
            jail_scratch = jail_root / "scratch.ext4"

            with timer.stage("jailed_playwright_guest", "portable"):
                execution = _run_jailed(
                    jailer=runtime["jailer"],
                    firecracker=runtime["firecracker"],
                    jail_base=runtime["jail_base"],
                    vm_id=vm_id,
                    uid=identity["uid"],
                    gid=identity["gid"],
                )

            with timer.stage("scratch_externalize", "portable"):
                _export_scratch(jail_scratch, exported_scratch)
                outputs = _inspect_outputs(exported_scratch, work)

            root_after = _sha256(rootfs)
            root_immutable = root_before == root_after == rootfs_info["rootfs_sha256"]
        finally:
            cleanup_actions = []
            if trusted_base.exists():
                rr = j1._sudo(["rm", "-rf", str(trusted_base)], timeout=120)
                cleanup_actions.append({"action": "trusted_base_remove", "ok": rr["ok"]})
            if identity is not None:
                rr = j1._delete_ephemeral_identity(identity)
                cleanup_actions.append({
                    "action": "ephemeral_identity_remove",
                    "ok": rr["userdel_ok"] and rr["groupdel_ok"],
                })
            cleanup = {
                "ok": all(a["ok"] for a in cleanup_actions) if cleanup_actions else True,
                "actions": cleanup_actions,
            }

        guest_supported = bool(execution.get("ok"))
        outputs_valid = bool(outputs.get("ok"))
        supported = guest_supported and outputs_valid and root_immutable and cleanup["ok"]
        if supported:
            final_classification = "SUPPORTED"
        elif not guest_supported:
            final_classification = execution.get("classification") or "WORKLOAD_FAILURE"
            if final_classification == "SUPPORTED":
                final_classification = "WORKLOAD_FAILURE"
        elif not outputs_valid or not root_immutable:
            final_classification = "ORACLE_FAILURE"
        else:
            final_classification = "CLEANUP_FAILURE"

        execution = {
            **execution,
            "classification": final_classification,
            "rootfs_immutable": root_immutable,
            "host_output_validation": outputs_valid,
            "cleanup_ok": cleanup["ok"],
        }

        receipt = evidence.make_receipt(
            authority_ref=AUTHORITY,
            assignment_ref=ASSIGNMENT,
            assignment_revision=ASSIGNMENT_REVISION,
            venue="public-gha",
            visibility="public_safe",
            placement_reasons=["stronger_isolation", "body_variation"],
            inputs={
                "playwright_release": PLAYWRIGHT_RELEASE,
                "playwright_version": PLAYWRIGHT_VERSION,
                "control_js_sha256": _sha256(CONTROL_JS),
                "control_html_sha256": _sha256(CONTROL_HTML),
                "bridge_init_sha256": _sha256(INIT_SOURCE),
            },
            body={
                "firecracker": {
                    "version": vm["version"],
                    "sha256": vm["archive_sha256"],
                },
                "kernel": {
                    "version": km["kernel_version"],
                    "sha256": km["kernel_sha256"],
                },
                "rootfs": {
                    "kind": "playwright-container-derived-squashfs",
                    "base_image_tag": rootfs_info.get("base_image_tag"),
                    "base_image_digest": rootfs_info.get("base_image_digest"),
                    "playwright": rootfs_info.get("tool_identity"),
                    "sha256": rootfs_info.get("rootfs_sha256"),
                    "size_bytes": rootfs_info.get("rootfs_size_bytes"),
                    "read_only_unchanged": root_immutable,
                },
                "resources": {
                    "vcpu_count": 2,
                    "mem_size_mib": 2048,
                    "network_interfaces": 0,
                    "scratch_size_bytes": 1024 * 1024 * 1024,
                    "jailer": True,
                },
            },
            execution=execution,
            outputs={
                "result_sha256": outputs.get("result_sha256"),
                "screenshot_sha256": outputs.get("screenshot_sha256"),
                "screenshot_size_bytes": outputs.get("screenshot_size_bytes"),
                "guest_result": outputs.get("result"),
            },
            validation={
                "accepted": False,
                "candidate_valid": outputs_valid,
                "validator_ref": "host/playwright-control-v1",
                "note": (
                    "Host-side debugfs extraction and semantic fixture validation are separate from guest self-report. "
                    "This same-run validator does not perform project acceptance; private reconciliation remains required."
                ),
            },
            cleanup=cleanup,
        )
        receipt["lifecycle_timing"] = timer.receipt()
        receipt["host_tools"] = tools
        receipt["kvm_access"] = {
            "classification": kvm_access.get("classification"),
            "mode": kvm_access.get("mode"),
            "kvm_api_version": kvm_access.get("kvm_api_version"),
        }
        receipt["runner"] = {
            "runner_os": os.getenv("RUNNER_OS"),
            "runner_arch": os.getenv("RUNNER_ARCH"),
            "image_os": os.getenv("ImageOS"),
            "image_version": os.getenv("ImageVersion"),
            "github_sha": os.getenv("GITHUB_SHA"),
        }
        receipt["receipt_digest"] = evidence.receipt_digest(receipt)
        return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args.label)
    except ProbeError as exc:
        receipt = {
            "schema": SCHEMA,
            "authority_ref": AUTHORITY,
            "assignment": {"ref": ASSIGNMENT, "revision": ASSIGNMENT_REVISION},
            "result": {
                "classification": exc.classification,
                "reason": exc.reason,
            },
        }
    except Exception as exc:
        receipt = {
            "schema": SCHEMA,
            "authority_ref": AUTHORITY,
            "assignment": {"ref": ASSIGNMENT, "revision": ASSIGNMENT_REVISION},
            "result": {
                "classification": "HARNESS_FAILURE",
                "reason": f"{type(exc).__name__}: {exc}",
            },
        }
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    classification = (receipt.get("execution") or receipt.get("result") or {}).get("classification")
    return 0 if classification == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
