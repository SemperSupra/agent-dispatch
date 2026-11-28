#!/usr/bin/env python3
"""Bounded static PE32+ x64 inspection of a released reference executable.

Header/section bounds, digest binding and unique RVA mapping reuse the public
rdte-pe-runtime-correspondence qualification principles at public source commit
da6229720542687adbf48d8a1e35a61b588bd9ec. Imports follow Microsoft's PE format:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

No executable is loaded or run. Preferred image addresses are not observed
runtime load addresses. This is a qualification adapter, not a general loader.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys


MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_IMPORT_DESCRIPTORS = 256
MAX_IMPORT_SYMBOLS = 16384
MAX_STRING_BYTES = 1024
MAX_RECOVERED_STRINGS = 96
STRING_INTEREST = re.compile(r"dos2unix|unix2dos|copyright|usage|convert|error|bom|utf-|binary|license", re.I)
DIRECTORY_NAMES = ["export", "import", "resource", "exception", "certificate",
                   "base_relocation", "debug", "architecture", "global_pointer", "tls",
                   "load_config", "bound_import", "iat", "delay_import", "clr", "reserved"]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class PEImage:
    def __init__(self, data: bytes):
        self.data = data
        self.sections: list[dict] = []
        self.size_of_headers = 0
        self.image_size = 0
        self.directories: list[dict] = []
        require(64 <= len(data) <= MAX_FILE_BYTES and data[:2] == b"MZ", "DOS signature or file bounds")
        offset = self.unpack("<I", 0x3C)[0]
        require(offset >= 64, "PE header overlaps DOS header")
        require(self.read(offset, 4) == b"PE\0\0", "PE signature")
        (machine, count, timestamp, symbol_pointer, symbol_count,
         optional_size, characteristics) = self.unpack("<HHIIIHH", offset + 4)
        require(machine == 0x8664 and 0 < count <= 96, "expected PE32+ x64 with bounded sections")
        require(characteristics & 0x0002, "PE is not marked executable")
        optional = offset + 24
        require(optional_size >= 112, "PE32+ optional header is truncated")
        self.read(optional, optional_size + count * 40)
        require(self.unpack("<H", optional)[0] == 0x20B, "expected PE32+ optional-header magic")
        self.entry_rva = self.unpack("<I", optional + 16)[0]
        self.image_base = self.unpack("<Q", optional + 24)[0]
        section_alignment, file_alignment = self.unpack("<II", optional + 32)
        self.image_size, self.size_of_headers = self.unpack("<II", optional + 56)
        subsystem, dll_characteristics = self.unpack("<HH", optional + 68)
        directory_count = self.unpack("<I", optional + 108)[0]
        require(0 < self.size_of_headers <= len(data) and self.image_size >= self.size_of_headers,
                "image/header sizes are invalid")
        require(optional + optional_size + count * 40 <= self.size_of_headers,
                "section table is outside SizeOfHeaders")
        require(self.image_base > 0 and self.image_base + self.image_size <= (1 << 64),
                "preferred image address range overflows")
        require(section_alignment > 0 and file_alignment > 0
                and section_alignment & (section_alignment - 1) == 0
                and file_alignment & (file_alignment - 1) == 0,
                "PE alignments must be positive powers of two")
        require(directory_count <= min(16, (optional_size - 112) // 8),
                "data directory table exceeds optional-header bounds")
        self.coff = self.coff_symbols(symbol_pointer, symbol_count)
        virtual_ranges = [(0, self.size_of_headers, "headers")]
        raw_ranges = [(0, self.size_of_headers, "headers")]
        for index in range(count):
            at = optional + optional_size + index * 40
            raw_name = self.read(at, 8).split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            if name.startswith("/") and name[1:].isdigit():
                name = self.coff_name(int(name[1:]))
            virtual_size, rva, raw_size, raw_pointer = self.unpack("<IIII", at + 8)
            flags = self.unpack("<I", at + 36)[0]
            span = max(virtual_size, raw_size)
            require(rva + span <= self.image_size, "section exceeds virtual image bounds")
            if span:
                self.non_overlapping(virtual_ranges, rva, rva + span, name, "virtual")
            if raw_size:
                self.read(raw_pointer, raw_size)
                self.non_overlapping(raw_ranges, raw_pointer, raw_pointer + raw_size, name, "file")
            self.sections.append({"index": index, "name": name, "rva": rva,
                                  "virtual_size": virtual_size, "mapped_span": span,
                                  "raw_size": raw_size, "raw_pointer": raw_pointer,
                                  "characteristics": flags, "executable": bool(flags & 0x20000000),
                                  "readable": bool(flags & 0x40000000),
                                  "writable": bool(flags & 0x80000000)})
        for index in range(directory_count):
            address, size = self.unpack("<II", optional + 112 + index * 8)
            directory = {"index": index, "name": DIRECTORY_NAMES[index],
                         "address": address, "size": size,
                         "address_kind": "file_offset" if index == 4 else "rva"}
            if size:
                require(address != 0, "data directory has size but no address")
                if index == 4:
                    self.read(address, size)
                else:
                    self.rva_to_offset(address, size)
            self.directories.append(directory)
        entry_offset, entry_section = self.rva_to_offset(self.entry_rva, 1)
        require(entry_section != "headers" and any(
            section["name"] == entry_section and section["executable"]
            and section["rva"] <= self.entry_rva < section["rva"] + section["mapped_span"]
            for section in self.sections), "entry RVA is not file-backed executable code")
        self.header = {"format": "PE32+", "machine": machine, "architecture": "x86_64",
                       "pe_header_offset": offset, "coff_timestamp_raw": timestamp,
                       "characteristics": characteristics, "optional_header_size": optional_size,
                       "preferred_image_base": self.image_base, "size_of_image": self.image_size,
                       "size_of_headers": self.size_of_headers, "entry_rva": self.entry_rva,
                       "entry_file_offset": entry_offset, "entry_section": entry_section,
                       "section_alignment": section_alignment, "file_alignment": file_alignment,
                       "subsystem": subsystem, "dll_characteristics": dll_characteristics}

    def read(self, offset: int, size: int) -> bytes:
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset,
                "read exceeds file bounds")
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int) -> tuple:
        return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt)))

    @staticmethod
    def non_overlapping(ranges, start, end, name, kind):
        require(not any(start < previous_end and previous_start < end
                        for previous_start, previous_end, _ in ranges),
                "overlapping " + kind + " section/header ranges")
        ranges.append((start, end, name))

    def rva_to_offset(self, rva: int, size: int) -> tuple[int, str]:
        require(size > 0 and 0 <= rva < self.image_size and size <= self.image_size - rva,
                "RVA range is outside the image")
        candidates = []
        if rva < self.size_of_headers and size <= self.size_of_headers - rva:
            candidates.append((rva, "headers"))
        for section in self.sections:
            delta = rva - section["rva"]
            if 0 <= delta < section["mapped_span"] and size <= section["mapped_span"] - delta:
                require(delta < section["raw_size"] and size <= section["raw_size"] - delta,
                        "RVA range is virtual-only rather than file-backed")
                candidates.append((section["raw_pointer"] + delta, section["name"]))
        require(len(candidates) == 1, "RVA range does not have exactly one file mapping")
        self.read(candidates[0][0], size)
        return candidates[0]

    def cstring_rva(self, rva: int) -> str:
        result = bytearray()
        for index in range(MAX_STRING_BYTES):
            offset, _ = self.rva_to_offset(rva + index, 1)
            char = self.data[offset]
            if char == 0:
                require(result and all(32 <= value <= 126 for value in result),
                        "import string is empty or not printable ASCII")
                return result.decode("ascii")
            result.append(char)
        raise ValueError("import string exceeds byte bound or is unterminated")

    def coff_symbols(self, pointer: int, count: int) -> dict:
        require(not count or pointer != 0, "COFF symbols have no table pointer")
        result = {"present": bool(pointer and count), "table_pointer": pointer,
                  "record_count_including_auxiliary": count, "record_size": 18,
                  "names_enumerated": False, "string_table_size": 0}
        self.coff_string_offset = None
        self.coff_string_size = 0
        if pointer:
            require(pointer >= self.size_of_headers, "COFF symbol table overlaps image headers")
            require(count <= MAX_FILE_BYTES // 18, "COFF symbol count exceeds bound")
            self.read(pointer, count * 18)
            string_offset = pointer + count * 18
            string_size = self.unpack("<I", string_offset)[0]
            require(string_size >= 4, "COFF string table is too small")
            self.read(string_offset, string_size)
            self.coff_string_offset, self.coff_string_size = string_offset, string_size
            result["string_table_size"] = string_size
        return result

    def coff_name(self, offset: int) -> str:
        require(self.coff_string_offset is not None and 4 <= offset < self.coff_string_size,
                "long section name has no valid COFF string-table offset")
        start = self.coff_string_offset + offset
        stop = min(self.coff_string_offset + self.coff_string_size, start + MAX_STRING_BYTES)
        end = self.data.find(b"\0", start, stop)
        require(end >= 0, "long section name exceeds COFF string table")
        return self.data[start:end].decode("ascii", errors="replace")

    def imports(self) -> dict:
        if len(self.directories) < 2 or not self.directories[1]["size"]:
            return {"dlls": [], "symbol_count": 0, "delay_imports_parsed": False}
        directory = self.directories[1]
        require(directory["size"] >= 20, "import directory is shorter than a descriptor")
        result = []
        symbol_count = 0
        terminated = False
        max_descriptors = min(directory["size"] // 20, MAX_IMPORT_DESCRIPTORS)
        for descriptor_index in range(max_descriptors):
            descriptor_rva = directory["address"] + descriptor_index * 20
            offset, _ = self.rva_to_offset(descriptor_rva, 20)
            lookup, timestamp, forwarder, name_rva, first_thunk = self.unpack("<IIIII", offset)
            if not any((lookup, timestamp, forwarder, name_rva, first_thunk)):
                terminated = True
                break
            require(name_rva and first_thunk, "import descriptor lacks DLL name or IAT")
            dll_name = self.cstring_rva(name_rva)
            table_rva = lookup or first_thunk
            symbols = []
            thunk_terminated = False
            for index in range(MAX_IMPORT_SYMBOLS + 1):
                at, _ = self.rva_to_offset(table_rva + index * 8, 8)
                thunk = self.unpack("<Q", at)[0]
                self.rva_to_offset(first_thunk + index * 8, 8)
                if thunk == 0:
                    thunk_terminated = True
                    break
                symbol_count += 1
                require(symbol_count <= MAX_IMPORT_SYMBOLS, "import symbol count exceeds bound")
                item = {"iat_rva": first_thunk + index * 8}
                if thunk & (1 << 63):
                    require(thunk & ~((1 << 63) | 0xFFFF) == 0, "ordinal import has reserved bits")
                    item["ordinal"] = thunk & 0xFFFF
                else:
                    require(thunk <= 0xFFFFFFFF, "import-by-name RVA exceeds 32 bits; bound IAT unsupported")
                    hint_offset, _ = self.rva_to_offset(thunk, 2)
                    item["hint"] = self.unpack("<H", hint_offset)[0]
                    item["name"] = self.cstring_rva(thunk + 2)
                symbols.append(item)
            require(thunk_terminated, "import lookup table lacks bounded terminator")
            result.append({"dll": dll_name, "descriptor_rva": descriptor_rva,
                           "lookup_table_rva": table_rva, "iat_rva": first_thunk,
                           "lookup_source": "original_first_thunk" if lookup else "iat_fallback",
                           "symbols": symbols})
        require(terminated, "import descriptor table lacks bounded terminator")
        return {"dlls": result, "symbol_count": symbol_count, "delay_imports_parsed": False}


def recovered_strings(data: bytes) -> dict:
    interesting = []
    ordinary = []
    total = 0
    for encoding, pattern in (("ascii", rb"[\x20-\x7e]{6,}"),
                              ("utf-16le-ascii-subset", rb"(?:[\x20-\x7e]\x00){6,}")):
        for match in re.finditer(pattern, data):
            total += 1
            raw = match.group()
            decoded = raw.decode("ascii" if encoding == "ascii" else "utf-16le")
            row = {"file_offset": match.start(), "byte_length": len(raw),
                   "encoding": encoding, "text": decoded[:256], "text_truncated": len(decoded) > 256}
            destination = interesting if STRING_INTEREST.search(decoded) else ordinary
            if len(destination) < MAX_RECOVERED_STRINGS:
                destination.append(row)
    rows = sorted((interesting + ordinary)[:MAX_RECOVERED_STRINGS], key=lambda row: row["file_offset"])
    return {"minimum_characters": 6, "maximum_results": MAX_RECOVERED_STRINGS,
            "maximum_display_characters": 256, "selection": "keyword matches first, then first ordinary runs",
            "keyword_pattern": STRING_INTEREST.pattern, "observed_run_count": total,
            "result_count": len(rows), "truncated": total > len(rows), "rows": rows,
            "interpretation": "Static byte strings; presence alone does not prove executed behavior."}


def inspect(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink(), "input must be a regular non-symlink file")
    require(path.stat().st_size <= MAX_FILE_BYTES, "input file exceeds static inspection bound")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    require(len(data) <= MAX_FILE_BYTES, "input grew beyond static inspection bound")
    pe = PEImage(data)
    return {
        "schema": "cre.windows_re.pe_static.v1", "status": "validated",
        "file": {"name": path.name, "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "header": pe.header, "sections": pe.sections, "data_directories": pe.directories,
        "imports": pe.imports(), "coff_symbols": pe.coff, "recovered_strings": recovered_strings(data),
        "validation": {"file_bounds": True, "section_ranges_non_overlapping": True,
                       "rva_mapping_unique": True, "entry_file_backed_executable": True},
        "provenance": {"inspected_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                       "github_sha": os.environ.get("GITHUB_SHA") or None,
                       "github_run_id": os.environ.get("GITHUB_RUN_ID") or None,
                       "public_parser_lineage": "SemperSupra/agent-dispatch@da6229720542687adbf48d8a1e35a61b588bd9ec",
                       "specification_url": "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"},
        "limits": ["Static preferred base is not an observed runtime load address.",
                   "COFF record availability is reported; symbols are not enumerated.",
                   "Delay imports, exports, relocations, debug records and signatures are not decoded.",
                   "Structural validation is not evidence of benign runtime behavior."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inspect(args.input)
        require(args.input.resolve() != args.output.resolve(), "output must differ from input")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ValueError, struct.error) as error:
        print(json.dumps({"schema": "cre.windows_re.pe_static.v1", "status": "failed",
                          "error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps({"schema": report["schema"], "status": report["status"],
                      "sha256": report["file"]["sha256"], "sections": len(report["sections"]),
                      "import_symbols": report["imports"]["symbol_count"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
