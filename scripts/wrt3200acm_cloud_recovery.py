#!/usr/bin/env python3
"""Cloud-only evidence collector for the WRT3200ACM firmware recovery campaign.

The script deliberately never emits acquired firmware payloads as result artifacts.
It downloads into a disposable work directory, records hashes/provenance and
derived observations, and writes reports only.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import time
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

UA = "SemperSupra-WRT3200ACM-recovery/1.0"
MAGICS = {
    "elf": b"\x7fELF",
    "gzip": b"\x1f\x8b\x08",
    "zip": b"PK\x03\x04",
    "xz": b"\xfd7zXZ\x00",
    "squashfs-le": b"hsqs",
    "squashfs-be": b"sqsh",
    "uimage": b"\x27\x05\x19\x56",
    "ubi-ec": b"UBI#",
    "fdt": b"\xd0\x0d\xfe\xed",
}
TEXT_MARKERS = [
    b"ThreadX", b"THREADX", b"Marvell", b"MRVL", b"88W8964",
    b"88W8897", b"88W8864", b"88W8997", b"Feroceon", b"ARM",
]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 120) -> dict[str, Any]:
    try:
        cp = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False
        )
        return {"cmd": cmd, "rc": cp.returncode, "stdout": cp.stdout[-20000:], "stderr": cp.stderr[-20000:]}
    except Exception as exc:
        return {"cmd": cmd, "rc": None, "error": repr(exc)}

def download(url: str, dest: Path, retries: int = 3) -> dict[str, Any]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    last: str | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            started = time.monotonic()
            with urllib.request.urlopen(req, timeout=45) as resp, dest.open("wb") as out:
                final_url = resp.geturl()
                content_type = resp.headers.get("Content-Type")
                total = 0
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    total += len(chunk)
            return {
                "ok": True, "attempt": attempt, "url": url, "final_url": final_url,
                "content_type": content_type, "size": total,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "sha256": sha256_file(dest),
            }
        except Exception as exc:
            last = repr(exc)
            if dest.exists():
                dest.unlink()
            time.sleep(min(2 ** attempt, 8))
    return {"ok": False, "url": url, "error": last}

def entropy(path: Path) -> float:
    counts = [0] * 256
    total = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            total += len(chunk)
            for b in chunk:
                counts[b] += 1
    if not total:
        return 0.0
    e = 0.0
    for c in counts:
        if c:
            p = c / total
            e -= p * math.log2(p)
    return round(e, 6)

def all_offsets(data: bytes, needle: bytes, cap: int = 256) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < cap:
        idx = data.find(needle, start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets

def magic_scan(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    result: dict[str, Any] = {}
    for name, magic in MAGICS.items():
        offs = all_offsets(data, magic, 128)
        if offs:
            result[name] = {"count_capped": len(offs), "offsets": offs}
    for marker in TEXT_MARKERS:
        offs = all_offsets(data, marker, 32)
        if offs:
            result["text:" + marker.decode("ascii", "replace")] = {"count_capped": len(offs), "offsets": offs}
    return result

CMD_RE = re.compile(r"^\s*#define\s+(HOSTCMD_CMD_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\b", re.M)
CMD_LABEL_RE = re.compile(r'\{\s*(HOSTCMD_CMD_[A-Z0-9_]+)\s*,\s*"([^"]+)"\s*\}')

def parse_mwlwifi(repo: Path, out: Path) -> dict[str, Any]:
    hostcmd_path = repo / "hif" / "hostcmd.h"
    fwcmd_path = repo / "hif" / "fwcmd.c"
    host = hostcmd_path.read_text(errors="replace")
    fw = fwcmd_path.read_text(errors="replace")
    labels = dict(CMD_LABEL_RE.findall(fw))
    cmds: list[dict[str, Any]] = []
    for name, value_s in CMD_RE.findall(host):
        value = int(value_s, 16)
        uses = [m.start() for m in re.finditer(r"\b" + re.escape(name) + r"\b", fw)]
        funcs: list[str] = []
        for pos in uses[:32]:
            prefix = fw[:pos]
            matches = list(re.finditer(
                r"(?m)^(?:static\s+)?(?:const\s+)?(?:struct\s+\w+\s*\*?|[A-Za-z_][\w\s\*]+?)\s+"
                r"(mwl_fwcmd_[A-Za-z0-9_]+)\s*\([^;]*\)\s*\{",
                prefix
            ))
            if matches:
                fn = matches[-1].group(1)
                if fn not in funcs:
                    funcs.append(fn)
        cmds.append({
            "name": name,
            "value": value,
            "hex": f"0x{value:04x}",
            "label": labels.get(name),
            "fwcmd_c_occurrences": len(uses),
            "functions": funcs,
        })
    catalog = {
        "schema": "mwlwifi-host-command-catalog/v1",
        "source_ref": run(["git", "rev-parse", "HEAD"], cwd=repo)["stdout"].strip(),
        "hostcmd_sha256": sha256_file(hostcmd_path),
        "fwcmd_sha256": sha256_file(fwcmd_path),
        "command_count": len(cmds),
        "commands": cmds,
    }
    (out / "mwlwifi-host-commands.json").write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")
    return catalog

def scan_command_words(path: Path, commands: list[dict[str, Any]], out: Path) -> dict[str, Any]:
    data = path.read_bytes()
    rows = []
    for cmd in commands:
        value = int(cmd["value"])
        le = struct.pack("<H", value)
        be = struct.pack(">H", value)
        le_offsets = all_offsets(data, le, 256)
        be_offsets = all_offsets(data, be, 256)
        rows.append({
            "name": cmd["name"], "value": value, "hex": cmd["hex"],
            "little_endian_count_capped": len(le_offsets),
            "little_endian_offsets": le_offsets,
            "big_endian_count_capped": len(be_offsets),
            "big_endian_offsets": be_offsets,
        })
    window_hits: dict[int, set[int]] = collections.defaultdict(set)
    known = {int(c["value"]) for c in commands}
    for off in range(0, len(data) - 1, 2):
        value = data[off] | (data[off + 1] << 8)
        if value in known:
            window_hits[(off // 512) * 512].add(value)
    candidates = sorted(
        (
            {"offset": off, "distinct_command_values": len(vals),
             "values": [f"0x{v:04x}" for v in sorted(vals)]}
            for off, vals in window_hits.items() if len(vals) >= 4
        ),
        key=lambda x: (-x["distinct_command_values"], x["offset"])
    )[:100]
    result = {
        "schema": "host-command-word-scan/v1",
        "artifact_sha256": sha256_file(path),
        "artifact_size": path.stat().st_size,
        "rows": rows,
        "candidate_windows_512b": candidates,
        "warning": "Raw constant matches are anchors only; they do not prove a dispatch table or handler."
    }
    (out / (path.name + ".hostcmd-scan.json")).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result

def strings_sample(path: Path, out: Path) -> None:
    r = run(["strings", "-a", "-n", "6", str(path)], timeout=120)
    lines = r.get("stdout", "").splitlines()
    sample = lines[:3000]
    (out / (path.name + ".strings.txt")).write_text("\n".join(sample) + ("\n" if sample else ""))

def inspect_archive(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if path.suffix in {".tgz", ".gz"} or path.name.endswith(".tar.gz"):
        result["tar_list"] = run(["tar", "-tzf", str(path)], timeout=120)
    result["7z_list"] = run(["7z", "l", "-ba", str(path)], timeout=120)
    return result

def marvell_record_map(path: Path) -> dict[str, Any]:
    """Parse the Marvell downloader record framing documented by ps4_wifi_bt.

    This is a format probe, not an assumption that every family member uses
    the same container. Unknown types or impossible sizes terminate the probe
    and remain explicit evidence.
    """
    data = path.read_bytes()
    off = 0
    records: list[dict[str, Any]] = []
    termination = "eof"
    valid_prefix = True
    while off + 16 <= len(data) and len(records) < 10000:
        rtype, load_addr, load_size, checksum = struct.unpack_from("<IIII", data, off)
        rec: dict[str, Any] = {
            "index": len(records),
            "file_offset": off,
            "type": rtype,
            "load_address": load_addr,
            "load_size": load_size,
            "header_checksum_field": checksum,
        }
        if rtype == 4:
            rec["meaning"] = "end"
            records.append(rec)
            off += 16
            termination = "type4-end"
            break
        if rtype == 6:
            rec["meaning"] = "split-marker"
            records.append(rec)
            off += 16
            continue
        if rtype != 1:
            rec["meaning"] = "unknown-type"
            records.append(rec)
            valid_prefix = False
            termination = "unknown-type"
            break
        if load_size < 4 or off + 16 + load_size > len(data):
            rec["meaning"] = "invalid-size"
            records.append(rec)
            valid_prefix = False
            termination = "invalid-size"
            break
        payload_off = off + 16
        payload_len = load_size - 4
        payload = data[payload_off:payload_off + payload_len]
        trailer = data[payload_off + payload_len:off + 16 + load_size]
        rec.update({
            "meaning": "load",
            "payload_file_offset": payload_off,
            "payload_size": payload_len,
            "payload_end_address": load_addr + payload_len,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "trailer_hex": trailer.hex(),
        })
        records.append(rec)
        off += 16 + load_size

    return {
        "schema": "marvell-download-record-map/v1",
        "artifact_sha256": sha256_file(path),
        "artifact_size": len(data),
        "head_256_hex": data[:256].hex(),
        "record_count": len(records),
        "valid_prefix": valid_prefix,
        "termination": termination,
        "consumed_bytes": off,
        "unconsumed_bytes": max(0, len(data) - off),
        "records": records,
        "provenance_note": (
            "Record semantics probed against x0rloser/ps4_wifi_bt fw_to_elf.py prior art; "
            "family compatibility must be independently validated."
        ),
    }


def targeted_tar_listing(path: Path) -> dict[str, Any]:
    pattern = re.compile(r"(?:88w|8964|8864|8897|8997|marvell|mwl|wlan|wireless|firmware|rango)", re.I)
    matches: list[str] = []
    count = 0
    error = None
    try:
        with tarfile.open(path, "r:gz") as tf:
            for member in tf:
                count += 1
                if pattern.search(member.name) and len(matches) < 10000:
                    matches.append(member.name)
    except Exception as exc:
        error = repr(exc)
    return {
        "schema": "targeted-archive-listing/v1",
        "artifact_sha256": sha256_file(path),
        "member_count_seen": count,
        "match_count_capped": len(matches),
        "matches": matches,
        "error": error,
    }


LEGACY_CMD_RE = re.compile(r"^\s*#define\s+(HostCmd_CMD_[A-Za-z0-9_]+)\s+(0x[0-9A-Fa-f]+)\b", re.M)


def compare_legacy_8864(current_catalog: dict[str, Any], work: Path, out: Path) -> dict[str, Any]:
    repo = work / "mrvl_wlan_v7drv"
    clone = run([
        "git", "clone", "--filter=blob:none", "--no-checkout",
        "https://github.com/DrakiaXYZ/mrvl_wlan_v7drv.git", str(repo)
    ], timeout=180)
    if clone.get("rc") != 0:
        result = {"schema": "legacy-hostcmd-overlap/v1", "status": "clone-failed", "detail": clone}
        (out / "legacy-8864-hostcmd-overlap.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    legacy_ref = "d87a75953857f809d5cd80ed3acd14bf9ebc39c0"
    checkout = run(["git", "checkout", "--detach", legacy_ref], cwd=repo, timeout=60)
    if checkout.get("rc") != 0:
        result = {"schema": "legacy-hostcmd-overlap/v1", "status": "checkout-failed", "detail": checkout}
        (out / "legacy-8864-hostcmd-overlap.json").write_text(json.dumps(result, indent=2) + "\n")
        return result

    hp = repo / "wlan-v7" / "core" / "incl" / "hostcmd.h"
    text = hp.read_text(errors="replace")
    legacy = {}
    for name, value_s in LEGACY_CMD_RE.findall(text):
        suffix = name[len("HostCmd_CMD_"):]
        legacy[suffix] = int(value_s, 16)
    current = {
        row["name"][len("HOSTCMD_CMD_"):]: int(row["value"])
        for row in current_catalog["commands"]
    }
    common = sorted(set(legacy) & set(current))
    same = [
        {"name": n, "value": current[n], "hex": f"0x{current[n]:04x}"}
        for n in common if current[n] == legacy[n]
    ]
    changed = [
        {"name": n, "legacy": legacy[n], "current": current[n]}
        for n in common if current[n] != legacy[n]
    ]
    result = {
        "schema": "legacy-hostcmd-overlap/v1",
        "status": "ok",
        "legacy_ref": legacy_ref,
        "legacy_hostcmd_sha256": sha256_file(hp),
        "legacy_command_count": len(legacy),
        "current_command_count": len(current),
        "name_overlap_count": len(common),
        "same_value_count": len(same),
        "changed_value_count": len(changed),
        "same_value": same,
        "changed_value": changed,
        "legacy_only": sorted(set(legacy) - set(current)),
        "current_only": sorted(set(current) - set(legacy)),
        "caveat": "Shared host command names/values establish protocol lineage, not firmware implementation identity."
    }
    (out / "legacy-8864-hostcmd-overlap.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--work", required=True)
    ns = ap.parse_args()
    manifest_path = Path(ns.manifest)
    out = Path(ns.out)
    work = Path(ns.work)
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(manifest_path.read_text())

    repo_dir = work / "mwlwifi"
    clone = run(["git", "clone", "--filter=blob:none", "--no-checkout",
                 "https://github.com/kaloz/mwlwifi.git", str(repo_dir)], timeout=180)
    if clone.get("rc") != 0:
        (out / "fatal.json").write_text(json.dumps({"stage": "clone-mwlwifi", "result": clone}, indent=2) + "\n")
        return 2
    checkout = run(["git", "checkout", "--detach", manifest["mwlwifi_commit"]], cwd=repo_dir, timeout=60)
    if checkout.get("rc") != 0:
        (out / "fatal.json").write_text(json.dumps({"stage": "checkout-mwlwifi", "result": checkout}, indent=2) + "\n")
        return 2

    catalog = parse_mwlwifi(repo_dir, out)
    legacy_overlap = compare_legacy_8864(catalog, work, out)
    inventory = {
        "schema": "wrt3200acm-cloud-inventory/v1",
        "manifest_sha256": sha256_file(manifest_path),
        "mwlwifi_commit": manifest["mwlwifi_commit"],
        "environment": {
            "python": sys.version,
            "platform": tuple(os.uname()),
            "github_run_id": os.getenv("GITHUB_RUN_ID"),
            "github_sha": os.getenv("GITHUB_SHA"),
        },
        "artifacts": []
    }

    target_blob: Path | None = None
    for src in manifest["sources"]:
        dest = work / "downloads" / src["filename"]
        rec: dict[str, Any] = {
            "id": src["id"], "kind": src["kind"], "url": src["url"],
            "required": bool(src.get("required", True)),
        }
        dl = download(src["url"], dest)
        rec["retrieval"] = dl
        if dl.get("ok"):
            rec["file"] = run(["file", "-b", str(dest)], timeout=30)
            rec["entropy_bits_per_byte"] = entropy(dest)
            rec["magic"] = magic_scan(dest)
            strings_sample(dest, out)
            if src["kind"] in {"gpl-source-archive", "oem-firmware", "openwrt-image"}:
                rec["archive_probe"] = inspect_archive(dest)
            if src["kind"] == "gpl-source-archive":
                targeted = targeted_tar_listing(dest)
                (out / (dest.name + ".targeted-listing.json")).write_text(json.dumps(targeted, indent=2, sort_keys=True) + "\n")
                rec["targeted_listing_report"] = dest.name + ".targeted-listing.json"
            if src["kind"] in {"target-radio-firmware", "related-radio-firmware", "third-radio-firmware"}:
                rec["hostcmd_scan_report"] = dest.name + ".hostcmd-scan.json"
                scan_command_words(dest, catalog["commands"], out)
                rmap = marvell_record_map(dest)
                (out / (dest.name + ".record-map.json")).write_text(json.dumps(rmap, indent=2, sort_keys=True) + "\n")
                rec["record_map_report"] = dest.name + ".record-map.json"
            if src["kind"] == "target-radio-firmware":
                target_blob = dest
        inventory["artifacts"].append(rec)

    (out / "inventory.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    summary = {
        "schema": "wrt3200acm-cloud-summary/v1",
        "required_total": sum(1 for x in inventory["artifacts"] if x["required"]),
        "required_retrieved": sum(1 for x in inventory["artifacts"] if x["required"] and x["retrieval"].get("ok")),
        "optional_failed": [x["id"] for x in inventory["artifacts"] if not x["required"] and not x["retrieval"].get("ok")],
        "host_command_count": catalog["command_count"],
        "legacy_8864_name_overlap_count": legacy_overlap.get("name_overlap_count"),
        "legacy_8864_same_value_count": legacy_overlap.get("same_value_count"),
        "target_88w8964_sha256": sha256_file(target_blob) if target_blob and target_blob.exists() else None,
        "target_88w8964_size": target_blob.stat().st_size if target_blob and target_blob.exists() else None,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["required_retrieved"] == summary["required_total"] else 3

if __name__ == "__main__":
    raise SystemExit(main())
