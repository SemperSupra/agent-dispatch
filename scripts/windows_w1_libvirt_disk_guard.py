#!/usr/bin/env python3
"""Fail-closed HOST-SIDE guard for a future Windows W1 DiskID=0 unattended wipe.

Does not infer Windows' guest disk enumeration, authorize Setup or write disks.
Requires independent guest-side Disk 0 identity evidence before any real wipe.
Authority: WinBot #108; public Windows W1 plans #508/#512/#513.
"""
from __future__ import annotations
import json
import os
import pathlib
import re
import stat
import subprocess
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Mapping

SCHEMA = "windows-w1-libvirt-host-disk-guard/v1"
SIZE = 64 * 1024 ** 3

class DiskGuardRefused(ValueError):
    pass

def need(ok: bool, why: str) -> None:
    if not ok:
        raise DiskGuardRefused(why)

def disk_image_observation(path: str) -> dict[str, Any]:
    """Read-only exact file and qemu-img metadata; never mutate or follow symlinks."""
    st = os.lstat(path)
    need(stat.S_ISREG(st.st_mode), "guest disk must be a regular file")
    need(not os.path.islink(path), "guest disk path is a symlink")
    parent = os.path.dirname(path)
    need(not os.path.islink(parent), "guest disk parent is a symlink")
    need(os.path.realpath(path) == path, "guest disk traverses a symlink")
    p = subprocess.run(["qemu-img", "info", "--output=json", path],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=30)
    info = json.loads(p.stdout)
    return {
        "path": path,
        "realpath": os.path.realpath(path),
        "regular_file": True,
        "symlink": False,
        "parent_symlink": False,
        "qemu_img": info,
    }

def verify_host_disk_guard(
    realized_domain_xml: str, *, run_uuid: str,
    image: Mapping[str, Any],
) -> dict[str, Any]:
    """A HOST-WIRING prerequisite, not proof that Windows Setup DiskID=0 is this disk."""
    try:
        uid = uuid.UUID(run_uuid)
    except (ValueError, TypeError, AttributeError) as exc:
        raise DiskGuardRefused("invalid run UUID") from exc
    need(uid.version == 4 and str(uid) == run_uuid, "noncanonical UUID v4")
    root = "/var/lib/libvirt/images/ad-w1-" + uid.hex
    expected_disk = root + "/system.qcow2"
    need(image.get("path") == expected_disk and image.get("realpath") == expected_disk,
         "image not exactly at owned source path")
    for flag, desired in (("regular_file", True), ("symlink", False),
                          ("parent_symlink", False)):
        need(image.get(flag) is desired, "file ownership/symlink evidence missing or unsafe")
    info = image.get("qemu_img")
    need(isinstance(info, Mapping), "missing qemu-img observation")
    need(info.get("format") == "qcow2" and
         type(info.get("virtual-size")) is int and info.get("virtual-size") == SIZE,
         "unexpected writable disk format or size")
    need(not info.get("backing-filename") and not info.get("full-backing-filename") and
         not info.get("backing-filename-format"),
         "guest image references an unowned backing file")
    try:
        dom = ET.fromstring(realized_domain_xml)
    except ET.ParseError as exc:
        raise DiskGuardRefused("invalid domain XML") from exc
    need(all(isinstance(el.tag, str) and not el.tag.startswith("{") for el in dom.iter()),
         "namespaced QEMU/libvirt device injection is not allowed")
    need(dom.tag == "domain" and dom.get("type") == "kvm", "not a KVM VM")
    need(dom.findtext("uuid") == run_uuid, "realized VM identity differs")
    need(dom.findtext("name") == "ad-w1-" + uid.hex, "realized VM name differs")
    need(not dom.findall("./devices/hostdev") and
         not dom.findall("./devices/filesystem") and
         not dom.findall("./devices/redirdev"),
         "other writable/host device passthrough present")
    disks = dom.findall("./devices/disk")
    need(len(disks) == 3, "expected exactly one system disk plus two optical media")
    writable = [d for d in disks if d.find("readonly") is None]
    need(len(writable) == 1 and writable[0].get("device") == "disk",
         "not exactly one writable system disk")
    system = writable[0]
    need(system.get("type") == "file", "system disk is not a regular image")
    source = system.find("source")
    driver = system.find("driver")
    target = system.find("target")
    need(source is not None and source.get("file") == expected_disk,
         "writable disk points outside owned system image")
    need(driver is not None and driver.get("name") == "qemu" and
         driver.get("type") == "qcow2", "unexpected guest image driver")
    need(target is not None and target.get("dev") == "sda" and
         target.get("bus") == "sata", "Windows boot/system disk is not unique SATA sda")
    backing = system.find("backingStore")
    need(backing is None or
         (backing.find("source") is None and backing.get("type") is None),
         "realized guest storage unexpectedly has backing source")
    expected_optical = {
        root + "/windows11-install.iso": "sdb",
        root + "/unattended-seed.iso": "sdc",
    }
    for disk in disks:
        if disk is system:
            continue
        src, tgt = disk.find("source"), disk.find("target")
        need(disk.get("device") == "cdrom" and disk.get("type") == "file" and
             disk.find("readonly") is not None and src is not None and tgt is not None,
             "unexpected non-readonly optical target")
        path = src.get("file")
        need(path in expected_optical and tgt.get("dev") == expected_optical[path] and
             tgt.get("bus") == "sata", "optical device is unowned or reordered")
        del expected_optical[path]
    need(not expected_optical, "missing expected optical disk")
    return {
        "schema": SCHEMA,
        "classification": "HOST_SINGLE_OWNED_DISK_CONFIRMED",
        "resource_uuid": run_uuid,
        "source_file": expected_disk,
        "observed_format": info["format"],
        "observed_virtual_size_bytes": SIZE,
        "one_writable_host_disk": True,
        "owned_optical_media_readonly": True,
        "guest_disk_zero_identity_confirmed": False,
        "windows_unattended_wipe_authorized": False,
        "windows_setup_started": False,
        "windows_guest_qualified": False,
        "winbot_guest_qualified": False,
        "next_gate": "independent Windows guest DiskID=0 observation + approved evaluation media/admission",
    }
