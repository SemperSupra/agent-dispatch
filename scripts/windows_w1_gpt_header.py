#!/usr/bin/env python3
"""Read-only validation of a primary GPT header recovered from an OWNED qcow2.

This validates only the host image's GPT identity; it is NOT a Windows PE
observation, installer/media admission, or permission to wipe any disk.
Windows DiskPart uniqueid disk must be independently compared later.
"""
from __future__ import annotations
import struct
import uuid
import zlib

class GPTIdentityRefused(ValueError):
    pass

def need(condition: bool, why: str) -> None:
    if not condition:
        raise GPTIdentityRefused(why)

def verify_gpt_primary(raw_early_sectors: bytes, *, expected_guid: str,
                       virtual_size_bytes: int) -> dict[str, object]:
    """Verify GPT primary header CRC, UUID, LBA range, and empty partition map.

    The exact 64 GiB production host image is selected by the caller. This
    function never reads a disk path, never writes, and never opens devices.
    """
    need(isinstance(raw_early_sectors, bytes) and len(raw_early_sectors) >= 1024,
         "missing primary GPT sector")
    need(type(virtual_size_bytes) is int and virtual_size_bytes % 512 == 0 and
         virtual_size_bytes >= 16 * 1024 * 1024, "invalid observed virtual capacity")
    need(isinstance(expected_guid, str), "host GPT GUID required")
    try:
        guid = uuid.UUID(expected_guid)
    except (ValueError, TypeError, AttributeError) as exc:
        raise GPTIdentityRefused("invalid expected GUID") from exc
    need(guid.version == 4 and str(guid) == expected_guid, "expected random canonical UUIDv4")
    header = raw_early_sectors[512:1024]
    need(header[:8] == b"EFI PART", "no GPT header signature")
    revision, length, stored_crc, reserved = struct.unpack_from("<IIII", header, 8)
    need(revision == 0x00010000 and 92 <= length <= 512 and reserved == 0,
         "unsupported GPT header revision/size/reserved")
    checksum = bytearray(header[:length])
    checksum[16:20] = bytes(4)
    need((zlib.crc32(checksum) & 0xffffffff) == stored_crc,
         "primary GPT header CRC differs")
    current_lba, backup_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", header, 24)
    need(current_lba == 1 and backup_lba == virtual_size_bytes // 512 - 1,
         "GPT primary/backup LBA not mapped to observed disk capacity")
    need(34 <= first_usable <= last_usable < backup_lba,
         "GPT usable range invalid")
    real_guid = uuid.UUID(bytes_le=header[56:72])
    need(real_guid == guid, "GPT disk GUID not equal to fresh run-owned expected value")
    entries_lba, entries_count, entry_size, entries_crc = struct.unpack_from("<QIII", header, 72)
    need(entries_lba == 2 and 1 <= entries_count <= 4096 and
         entry_size >= 128 and entry_size % 8 == 0,
         "GPT entry array is not conventional/readable")
    table_bytes = entries_count * entry_size
    need(len(raw_early_sectors) >= (entries_lba * 512 + table_bytes),
         "partition table not fully observed")
    entries = raw_early_sectors[entries_lba * 512:entries_lba * 512 + table_bytes]
    need((zlib.crc32(entries) & 0xffffffff) == entries_crc,
         "GPT partition table CRC differs")
    need(not any(entries), "not an empty run-owned GPT disk: refuse")
    return {
        "schema": "winbot-w1-host-gpt-id/v1",
        "classification": "OWNED_HOST_GPT_GUID_VERIFIED",
        "disk_guid": str(real_guid),
        "virtual_size_bytes": virtual_size_bytes,
        "primary_header_crc_valid": True,
        "empty_partition_table_crc_valid": True,
        "backup_lba": backup_lba,
        "host_only": True,
        "actual_winpe_observed": False,
        "destructive_windows_setup_authorized": False,
        "windows_guest_qualified": False,
        "winbot_guest_qualified": False,
    }
