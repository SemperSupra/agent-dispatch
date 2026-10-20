#!/usr/bin/env python3
"""$0 public-host disposable GPT GUID preseed/readback inside sparse qcow2.

Creates ONLY a fresh 64 GiB VIRTUAL disk stored as a sparse file in a new,
run-owned /tmp dir. Never opens /dev, touches host disks, downloads Windows,
launches WinPE, or authorizes unattended disk operations. Probe only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from scripts.windows_w1_gpt_header import verify_gpt_primary

CAPACITY = 64 * 1024**3
EVIDENCE = Path("/tmp/winbot-host-gpt-evidence")

def run_cmd(args: list[str], timeout: int = 180) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True, timeout=timeout)
    return result.stdout

def record(name: str, value: object) -> None:
    (EVIDENCE / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def main() -> int:
    if EVIDENCE.exists():
        print("preexisting evidence path: refusing", file=sys.stderr)
        return 4
    EVIDENCE.mkdir(mode=0o700)
    owner = "ad-winbot-gpt-" + uuid.uuid4().hex
    root = Path("/tmp") / owner
    guid = str(uuid.uuid4())
    owned = False
    failure: str | None = None
    try:
        if root.exists() or root.is_symlink():
            raise ValueError("refusing preexisting owner directory")
        root.mkdir(mode=0o700)
        owned = True
        raw = root / "raw-sparse-64g.img"
        qcow = root / "owned-system.qcow2"
        early = root / "first-34-sectors.raw"
        fd = os.open(raw, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.ftruncate(fd, CAPACITY)
        finally:
            os.close(fd)
        # Only operate on a fresh regular file with an exact unique path.
        run_cmd(["sgdisk", "--clear", "--disk-guid=" + guid, str(raw)])
        run_cmd(["sgdisk", "--verify", str(raw)])
        gpt_report = run_cmd(["sgdisk", "--print", str(raw)])
        if "Disk identifier (GUID): " + guid.upper() not in gpt_report:
            raise ValueError("sgdisk did not read back fresh disk GUID")
        run_cmd(["qemu-img", "convert", "-f", "raw", "-O", "qcow2",
                 "-S", "4096", str(raw), str(qcow)], timeout=420)
        info = json.loads(run_cmd(["qemu-img", "info", "--output=json", str(qcow)]))
        if info.get("format") != "qcow2" or info.get("virtual-size") != CAPACITY or \
                info.get("backing-filename") or info.get("full-backing-filename"):
            raise ValueError("sparse qcow2 size/format/backing mismatch")
        run_cmd(["qemu-img", "dd", "-f", "qcow2", "bs=512", "count=34",
                 "if=" + str(qcow), "of=" + str(early)], timeout=60)
        observed = verify_gpt_primary(early.read_bytes(),
                                      expected_guid=guid,
                                      virtual_size_bytes=CAPACITY)
        if not observed.get("empty_partition_table_crc_valid"):
            raise ValueError("no empty GPT table proof")
        recorded = {
            "schema": "winbot-w1-host-qcow2-gpt-proof/v1",
            "classification": "HOST_GPT_IDENTITY_ONLY",
            "run_owner": owner,
            "gpt_identity": observed,
            "qemu_image_virtual_size": info.get("virtual-size"),
            "qemu_image_format": info.get("format"),
            "qemu_image_allocated_bytes": qcow.stat().st_blocks * 512,
            "actual_windows_pe_executed": False,
            "real_windows_iso_downloaded": False,
            "guest_disk_zero_identified": False,
            "windows_setup_authorized": False,
            "windows_installed": False,
            "winbot_guest_qualified": False,
        }
        record("host-gpt-proof.json", recorded)
        # Never publish huge raw/qcow2 bytes; they are local disposable files.
    except Exception as ex:
        failure = type(ex).__name__ + ": " + str(ex)
        record("error.json", {"classification": "HARNESS_OR_ENVIRONMENT_FAILURE",
                              "reason": failure[:1500]})
    finally:
        if owned:
            shutil.rmtree(root)
        absent = not root.exists() and not root.is_symlink()
        record("cleanup.json", {"schema": "winbot-host-gpt-cleanup/v1",
                                "run_owned_files_absent": absent,
                                "initial_failure": failure,
                                "windows_media_touched": False,
                                "external_disks_mutated": False})
        if not absent:
            failure = "CLEANUP_FAILURE: disposable image files not absent"
    if failure:
        print(failure, file=sys.stderr)
        return 3
    print("HOST qcow2 GPT ID source verified; NO Windows/WinPE and no W1 admission")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
