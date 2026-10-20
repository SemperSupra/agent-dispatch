#!/usr/bin/env python3
"""Read-only Windows PE disk-identity evidence contract for WinBot standalone KVM.

No Windows media, Windows Setup, disk writes, credential access, or VM mutation.
This is not guest-side runtime proof; it validates a future external serial
transcript against a separately observed host-owned GPT GUID and host guard.
Microsoft DiskPart 'uniqueid disk' displays GPT disk GUID without id=.
"""
from __future__ import annotations
import hashlib
import re
import uuid
from typing import Any, Mapping

SCHEMA = "winbot-w1-winpe-disk-identity-oracle/v1"
HOST_SCHEMA = "windows-w1-libvirt-host-disk-guard/v1"
NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
DISK_ROW = re.compile(r"(?im)^\s*Disk\s+([0-9]+)\s+(Online|Offline|No Media|Not Initialized)\s+(\d+)\s+(GB|TB|MB)\s+")
GUID_LINE = re.compile(r"(?im)^\s*Disk ID:\s*\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?\s*$")

class DiskIdentityRefused(ValueError):
    pass

def require(ok: bool, detail: str) -> None:
    if not ok:
        raise DiskIdentityRefused(detail)

def diskpart_readonly_commands() -> str:
    """No DiskPart write operations."""
    return "list disk\nselect disk 0\nuniqueid disk\nexit\n"

def _canonical_uuid(value: Any) -> str:
    require(isinstance(value, str), "UUID must be exact text")
    try:
        parsed = uuid.UUID(value)
    except (TypeError, ValueError, AttributeError) as exc:
        raise DiskIdentityRefused("invalid UUID") from exc
    require(parsed.version == 4 and str(parsed) == value.lower(),
            "expected valid UUIDv4")
    return str(parsed)

def classify_winpe_serial(
    text: str,
    *,
    expected_nonce: str,
    expected_run_uuid: str,
    host_gpt_disk_guid: str,
    host_gpt_guid_observed: bool,
    host_guard: Mapping[str, Any],
    read_only_script_sha256: str,
    read_only_script_independently_verified: bool,
) -> dict[str, Any]:
    """Require separately trusted host GPT readback and external guest serial.

    Caller must prove a real admitted Windows PE guest produced the serial; this
    parser does not claim a Windows runtime or authorize destructive installation.
    """
    require(isinstance(expected_nonce, str) and NONCE.fullmatch(expected_nonce) is not None,
            "nonce grammar invalid")
    require(isinstance(text, str) and len(text) <= 20000, "transcript missing or too large")
    uid = _canonical_uuid(expected_run_uuid)
    guid = _canonical_uuid(host_gpt_disk_guid)
    require(host_gpt_guid_observed is True, "GPT GUID must be independently read from run-owned disk")
    require(isinstance(host_guard, Mapping) and host_guard.get("schema") == HOST_SCHEMA,
            "exact host guard receipt absent")
    require(host_guard.get("classification") == "HOST_SINGLE_OWNED_DISK_CONFIRMED",
            "host disk identity not independently verified")
    require(host_guard.get("resource_uuid") == uid and
            host_guard.get("one_writable_host_disk") is True and
            host_guard.get("windows_unattended_wipe_authorized") is False,
            "host guard does not bind this run or refuses mutation")
    require(host_guard.get("source_file") ==
            "/var/lib/libvirt/images/ad-w1-" + uuid.UUID(uid).hex + "/system.qcow2",
            "host guard path mismatch")

    script_sha=hashlib.sha256(diskpart_readonly_commands().encode("utf-8")).hexdigest()
    require(read_only_script_independently_verified is True and
            read_only_script_sha256 == script_sha,
            "independent pinned read-only DiskPart script SHA256 missing/mismatched")
    first = "AD_W1_WINPE_BEGIN=" + expected_nonce
    last = "AD_W1_WINPE_END=" + expected_nonce
    require(text.count(first) == 1 and text.count(last) == 1,
            "exact one begin/end serial envelope required")
    begin, end = text.index(first), text.index(last)
    require(begin < end, "reordered serial transcript")
    body = text[begin + len(first):end]
    require(text.count("Disk ID:") == 1, "disk IDs outside envelope or duplicated")
    # Native Windows DiskPart /s output DOES NOT ECHO input commands. Exact
    # readonly command provenance must instead be proven by an independent
    # source/seed digest, never inferred from the output transcript itself.
    require("DISKPART>" not in body, "interactive command echo not supported by this oracle")
    require(body.count("Microsoft DiskPart version") == 1 and
            body.count("Leaving DiskPart...") == 1,
            "native DiskPart start/finish provenance not observed")
    selected_lines = list(re.finditer(
        r"(?im)^Disk 0 is now the selected disk\.\s*$", body))
    require(len(selected_lines) == 1, "DiskPart did not select exactly disk zero")
    listing = body[:selected_lines[0].start()]
    matches = DISK_ROW.findall(listing)
    all_disk_rows = re.findall(r"(?im)^\s*Disk\s+([0-9]+)\b", listing)
    require(len(all_disk_rows) == len(matches), "unrecognized disk status/extra disk row")
    require(len(matches) == 1 and matches[0][0] == "0" and
            matches[0][1].lower() == "online" and
            matches[0][2] == "64" and matches[0][3] == "GB",
            "guest DiskPart list disk did not observe only one online 64 GB disk zero")
    ids = GUID_LINE.findall(body[selected_lines[0].end():])
    require(len(ids) == 1 and ids[0].lower() == guid,
            "guest disk zero GPT GUID does not equal independently observed host GUID")
    require("DiskPart has encountered an error" not in body and
            "There is no disk selected" not in body,
            "Windows PE reported disk error")
    return {
        "schema": SCHEMA,
        "classification": "GUEST_TRANSCRIPT_MATCHES_HOST_GPT_IDENTITY",
        "resource_uuid": uid,
        "observed_disk_index": 0,
        "observed_host_gpt_guid": guid,
        "observed_guest_gpt_guid": ids[0].lower(),
        "single_online_disk": True,
        "host_guard_matched": True,
        "read_only_script_sha256_matched": True,
        "guest_media_provenance_independently_proved": False,
        "destructive_windows_setup_authorized": False,
        "windows_installed": False,
        "winbot_guest_qualified": False,
        "claim_boundary": "source-only parser until real Windows PE serial provenance is independently attested",
    }
