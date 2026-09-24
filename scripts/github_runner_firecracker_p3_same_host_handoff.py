#!/usr/bin/env python3
"""P3 same-host Firecracker snapshot handoff: A -> snapshot -> B -> continuity."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import github_runner_firecracker_f0 as f0
import github_runner_firecracker_f1_boot as f1
import firecracker_execution_adapter as exec_adapter
from firecracker_lifecycle_timing import LifecycleTimer

SCHEMA = "firecracker-p3-same-host-handoff-receipt/v1"
PROBE_VERSION = "firecracker-p3-same-host-handoff/1"
VMM_MANIFEST = pathlib.Path("experiments/firecracker/firecracker-v1.17.0-x86_64.json")
KERNEL_MANIFEST = pathlib.Path("experiments/firecracker/guest-kernel-6.18.48-x86_64.json")
INIT_SOURCE = pathlib.Path("experiments/firecracker/p3/snapshot-continuity-init-x86_64.c")
READY_RE = re.compile(r"FIRECRACKER_P3_READY counter=(\d+)")
HEARTBEAT_RE = re.compile(r"FIRECRACKER_P3_HEARTBEAT counter=(\d+)")
DONE_RE = re.compile(r"FIRECRACKER_P3_DONE counter=(\d+)")


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _api(socket_path: pathlib.Path, method: str, endpoint: str, payload: dict) -> dict:
    curl = shutil.which("curl")
    access = exec_adapter.select_kvm_access()
    if not curl or access.get("classification") != "SUPPORTED":
        return {"ok": False, "reason": "curl or qualified KVM execution boundary unavailable", "kvm_access": access}
    body = json.dumps(payload, separators=(",", ":"))
    started = time.perf_counter()
    cp = subprocess.run(
        exec_adapter.api_command(
            curl,
            socket_path,
            [
                "-sS", "--fail-with-body",
                "-X", method,
                "-H", "Content-Type: application/json",
                "-d", body,
                f"http://localhost{endpoint}",
            ],
            access,
        ),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return {
        "ok": cp.returncode == 0,
        "return_code": cp.returncode,
        "elapsed_ms": round((time.perf_counter()-started)*1000.0, 3),
        "stdout": cp.stdout.strip()[-2000:],
        "stderr": cp.stderr.strip()[-2000:],
    }


def _wait_for_socket(path: pathlib.Path, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.01)
    return False


def _reader(proc: subprocess.Popen, lines: list[str], stop: threading.Event) -> None:
    assert proc.stdout is not None
    while not stop.is_set():
        line = proc.stdout.readline()
        if line == "":
            if proc.poll() is not None:
                break
            time.sleep(0.01)
            continue
        lines.append(line.rstrip("\n"))


def _wait_for_regex(lines: list[str], regex: re.Pattern, timeout_s: float) -> re.Match | None:
    deadline = time.monotonic() + timeout_s
    scanned = 0
    while time.monotonic() < deadline:
        snapshot = list(lines)
        for line in snapshot[scanned:]:
            match = regex.search(line)
            if match:
                return match
        scanned = len(snapshot)
        time.sleep(0.01)
    return None


def _all_heartbeat_values(lines: list[str]) -> list[int]:
    values = []
    for line in list(lines):
        match = HEARTBEAT_RE.search(line)
        if match:
            values.append(int(match.group(1)))
    return values


def _launch(binary: pathlib.Path, api_socket: pathlib.Path, config: pathlib.Path | None = None) -> subprocess.Popen:
    access = exec_adapter.select_kvm_access()
    if access.get("classification") != "SUPPORTED":
        raise RuntimeError("qualified KVM execution boundary unavailable")
    args = ["--api-sock", str(api_socket.resolve())]
    if config is not None:
        args += ["--config-file", str(config.resolve())]
    argv = exec_adapter.firecracker_command(binary, args, access)
    return subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )


def _actual_firecracker_pid(api_socket: pathlib.Path) -> int | None:
    target = str(api_socket)
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text().strip()
            if not comm.startswith("firecracker"):
                continue
            cmdline = (entry / "cmdline").read_bytes().decode(errors="ignore").replace("\0", " ")
            if target in cmdline:
                return int(entry.name)
        except (OSError, ValueError):
            continue
    return None


def _terminate_group(proc: subprocess.Popen, timeout_s: float = 3.0) -> dict:
    started = time.perf_counter()
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        rc = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        rc = proc.wait(timeout=2)
    return {"return_code": rc, "elapsed_ms": round((time.perf_counter()-started)*1000.0, 3)}


def _build_initramfs(init_binary: pathlib.Path, output: pathlib.Path) -> None:
    import stat
    payload = b"".join([
        f1._newc_entry(".", mode=stat.S_IFDIR | 0o755, ino=1, nlink=2),
        f1._newc_entry("dev", mode=stat.S_IFDIR | 0o755, ino=2, nlink=2),
        f1._newc_entry("dev/console", mode=stat.S_IFCHR | 0o600, ino=3, rdevmajor=5, rdevminor=1),
        f1._newc_entry("init", mode=stat.S_IFREG | 0o755, data=init_binary.read_bytes(), ino=4),
        f1._newc_entry("TRAILER!!!", mode=0, ino=5),
    ])
    output.write_bytes(payload)


def run_probe(label: str) -> dict:
    timer = LifecycleTimer()
    vm_manifest = f1._load_json(VMM_MANIFEST)
    kernel_manifest = f1._load_json(KERNEL_MANIFEST)

    with tempfile.TemporaryDirectory(prefix="firecracker-p3-") as td:
        w = pathlib.Path(td)
        archive, kernel = w/"firecracker.tgz", w/"vmlinux"
        extract = w/"vmm"; extract.mkdir()
        init_bin, initrd, config_path = w/"init", w/"initrd.cpio", w/"source-config.json"
        source_sock, dest_sock = w/"source.sock", w/"dest.sock"
        state_file, mem_file = w/"snapshot.state", w/"snapshot.mem"

        with timer.stage("vmm_download_and_verify","venue"):
            vv=f1._download_and_verify(vm_manifest["archive_url"],vm_manifest["archive_sha256"],archive)
        with timer.stage("vmm_extract","portable"):
            f0._safe_extract(archive,extract)
            firecracker=f1._find_firecracker(extract,vm_manifest["version"],vm_manifest["architecture"])
        with timer.stage("kernel_download_and_verify","venue"):
            kv=f1._download_and_verify(kernel_manifest["kernel_url"],kernel_manifest["kernel_sha256"],kernel)
        with timer.stage("guest_init_compile","portable"):
            ic=f1._compile_init(INIT_SOURCE,init_bin)
        if not vv["verified"] or not kv["verified"] or not ic["ok"]:
            return {"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE"}}
        with timer.stage("initramfs_build","portable"):
            _build_initramfs(init_bin,initrd)
        with timer.stage("vm_config_build","portable"):
            config=f1._build_config(kernel,initrd,config_path)

        source_lines: list[str] = []
        source_stop=threading.Event()
        with timer.stage("source_start_to_ready","portable"):
            source=_launch(firecracker,source_sock,config_path)
            source_reader=threading.Thread(target=_reader,args=(source,source_lines,source_stop),daemon=True)
            source_reader.start()
            if not _wait_for_socket(source_sock,5):
                _terminate_group(source)
                return {"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":"source API socket not ready"}}
            ready=_wait_for_regex(source_lines,READY_RE,5)
            first_hb=_wait_for_regex(source_lines,HEARTBEAT_RE,5)
            if not ready or not first_hb:
                _terminate_group(source)
                return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"source READY/heartbeat not observed"}}

        source_pid=_actual_firecracker_pid(source_sock)

        handoff_started=time.perf_counter()
        with timer.stage("pause_api","portable"):
            pause=_api(source_sock,"PATCH","/vm",{"state":"Paused"})
        if not pause["ok"]:
            _terminate_group(source)
            return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"pause failed","pause":pause}}
        time.sleep(0.05)
        source_heartbeats=_all_heartbeat_values(source_lines)
        source_last_counter=max(source_heartbeats) if source_heartbeats else None

        with timer.stage("snapshot_create_full","portable"):
            create=_api(source_sock,"PUT","/snapshot/create",{
                "snapshot_type":"Full",
                "snapshot_path":str(state_file.resolve()),
                "mem_file_path":str(mem_file.resolve()),
                "sync_snapshot_files":True,
            })
        if not create["ok"] or not state_file.exists() or not mem_file.exists():
            _terminate_group(source)
            return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"snapshot create failed","create":create}}

        snapshot_meta={
            "state_size_bytes":state_file.stat().st_size,
            "mem_size_bytes":mem_file.stat().st_size,
        }

        with timer.stage("source_termination","portable"):
            source_term=_terminate_group(source)
        source_stop.set()
        source_reader.join(timeout=1)
        source_pid_after=_actual_firecracker_pid(source_sock)

        dest_lines: list[str]=[]
        dest_stop=threading.Event()
        with timer.stage("destination_process_start","portable"):
            dest=_launch(firecracker,dest_sock,None)
            dest_reader=threading.Thread(target=_reader,args=(dest,dest_lines,dest_stop),daemon=True)
            dest_reader.start()
            if not _wait_for_socket(dest_sock,5):
                _terminate_group(dest)
                return {"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":"destination API socket not ready"}}
        dest_pid=_actual_firecracker_pid(dest_sock)

        with timer.stage("snapshot_load","portable"):
            load=_api(dest_sock,"PUT","/snapshot/load",{
                "snapshot_path":str(state_file.resolve()),
                "mem_backend":{"backend_path":str(mem_file.resolve()),"backend_type":"File"},
                "track_dirty_pages":False,
                "resume_vm":False,
            })
        if not load["ok"]:
            _terminate_group(dest)
            return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"snapshot load failed","load":load}}

        resume_started=time.perf_counter()
        with timer.stage("resume_api","portable"):
            resume=_api(dest_sock,"PATCH","/vm",{"state":"Resumed"})
        if not resume["ok"]:
            _terminate_group(dest)
            return {"schema":SCHEMA,"result":{"classification":"ORACLE_FAILURE","reason":"resume failed","resume":resume}}

        first_dest_hb=_wait_for_regex(dest_lines,HEARTBEAT_RE,5)
        resume_to_output_ms=round((time.perf_counter()-resume_started)*1000.0,3) if first_dest_hb else None
        if resume_to_output_ms is not None:
            timer.add("resume_to_first_guest_output","portable",resume_to_output_ms,derived=True)
            timer.add("source_pause_request_to_destination_output","portable",(time.perf_counter()-handoff_started)*1000.0,derived=True)

        try:
            dest_rc=dest.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dest_term=_terminate_group(dest)
            dest_rc=dest_term["return_code"]
        dest_stop.set()
        dest_reader.join(timeout=1)

        dest_ready_seen=any(READY_RE.search(line) for line in dest_lines)
        dest_heartbeats=_all_heartbeat_values(dest_lines)
        dest_first_counter=dest_heartbeats[0] if dest_heartbeats else None
        done_values=[int(m.group(1)) for line in dest_lines if (m:=DONE_RE.search(line))]
        with timer.stage("snapshot_hash_receipt","portable"):
            snapshot_meta["state_sha256"]=_sha256(state_file)
            snapshot_meta["mem_sha256"]=_sha256(mem_file)

        continuity_ok=(
            source_pid is not None
            and dest_pid is not None
            and source_pid != dest_pid
            and source_pid_after is None
            and source_last_counter is not None
            and dest_first_counter is not None
            and dest_first_counter > source_last_counter
            and not dest_ready_seen
            and bool(done_values)
            and max(done_values) == 20
            and dest_rc == 0
        )

        return {
            "schema":SCHEMA,
            "probe_version":PROBE_VERSION,
            "authority":"SemperSupra/agent-dispatch-private#280",
            "requested_label":label,
            "result":{
                "classification":"SUPPORTED" if continuity_ok else "ORACLE_FAILURE",
                "continuity_oracle_satisfied":continuity_ok,
                "source_firecracker_pid":source_pid,
                "destination_firecracker_pid":dest_pid,
                "source_absent_before_resume":source_pid_after is None,
                "destination_reemitted_ready":dest_ready_seen,
                "source_last_heartbeat_counter":source_last_counter,
                "destination_first_heartbeat_counter":dest_first_counter,
                "destination_done_counter":max(done_values) if done_values else None,
                "destination_exit_code":dest_rc,
            },
            "snapshot":snapshot_meta,
            "api":{
                "pause":pause,
                "create":create,
                "load":load,
                "resume":resume,
                "source_termination":source_term,
            },
            "portable":{
                "vmm_version":vm_manifest["version"],
                "vmm_archive_sha256":vv["actual_sha256"],
                "kernel_version":kernel_manifest["kernel_version"],
                "kernel_sha256":kv["actual_sha256"],
                "guest_init_source":str(INIT_SOURCE),
                "guest_init_binary_sha256":f1._sha256(init_bin),
                "initrd_sha256":f1._sha256(initrd),
                "machine":{"vcpu_count":config["machine-config"]["vcpu_count"],"mem_size_mib":config["machine-config"]["mem_size_mib"],"drives":0,"network_interfaces":0},
            },
            "lifecycle_timing":timer.receipt(),
            "source_output_tail":"\n".join(source_lines[-80:]),
            "destination_output_tail":"\n".join(dest_lines[-80:]),
            "sovereign_transfer":{
                "portable_contract_depends_on_github_actions":False,
                "handoff_semantics":"pause -> full snapshot -> terminate source -> fresh process load -> resume",
                "source_never_resumed_after_snapshot":True,
            },
        }


def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args(); a.out.parent.mkdir(parents=True,exist_ok=True)
    try:
        receipt=run_probe(a.label)
    except Exception as exc:
        receipt={"schema":SCHEMA,"result":{"classification":"HARNESS_FAILURE","reason":f"{type(exc).__name__}: {exc}"}}
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["result"]["classification"]=="SUPPORTED" else 1


if __name__=="__main__":
    raise SystemExit(main())
