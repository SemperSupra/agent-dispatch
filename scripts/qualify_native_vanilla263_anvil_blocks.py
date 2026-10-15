#!/usr/bin/env python3
"""Bounded independent Minecraft Anvil region *source* decoder, G4 candidate.

Accepts raw region bytes only. Admission of bytes as live SERVER-OWNED world
requires a separate authenticated fixed-path native TrueNAS read at explicit
quiesced checkpoints. This module alone NEVER asserts backend world proof,
COLLAGE APPLY, authenticated clients or a successful guest.
"""
from __future__ import annotations

import hashlib
import math
import struct
import zlib

SCHEMA = "supracraft.native-vanilla263-server-owned-anvil/1"
MAX_REGION = 64 * 1024 * 1024
MAX_CHUNK = 16 * 1024 * 1024
MAX_ITEMS = 1_000_000
COORDINATES = ((0, 70, 0), (2, 70, 0), (1, 70, 1))
EXPECTED = {
    "candidate": ("minecraft:redstone_block", "minecraft:air", "minecraft:sea_lantern"),
    "rollback": ("minecraft:redstone_block", "minecraft:iron_bars", "minecraft:black_concrete"),
}


class Refused(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


class NBT:
    def __init__(self, data: bytes):
        require(type(data) is bytes and 0 < len(data) <= MAX_CHUNK, "NBT_SIZE")
        self.data, self.i = data, 0

    def raw(self, n):
        require(type(n) is int and 0 <= n <= len(self.data) - self.i,
                "NBT_TRUNCATED")
        result = self.data[self.i:self.i+n]
        self.i += n
        return result

    def num(self, fmt):
        return struct.unpack(">" + fmt, self.raw(struct.calcsize(">" + fmt)))[0]

    def string(self):
        n = self.num("H")
        require(n <= 4096, "NBT_STRING_TOO_LONG")
        try:
            return self.raw(n).decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Refused("NBT_UTF8_INVALID") from None

    def payload(self, tag, depth=0):
        require(depth <= 24, "NBT_RECURSION")
        if tag == 1: return self.num("b")
        if tag == 2: return self.num("h")
        if tag == 3: return self.num("i")
        if tag == 4: return self.num("q")
        if tag == 5: return self.num("f")
        if tag == 6: return self.num("d")
        if tag == 8: return self.string()
        if tag in (7, 11, 12):
            n = self.num("i")
            width, fmt = {7:(1,"b"), 11:(4,"i"), 12:(8,"q")}[tag]
            require(0 <= n <= MAX_ITEMS and n*width <= len(self.data)-self.i,
                    "NBT_ARRAY_BOUNDS")
            return [self.num(fmt) for _ in range(n)]
        if tag == 9:
            nested = self.num("B")
            n = self.num("i")
            require(1 <= nested <= 12 and 0 <= n <= MAX_ITEMS,
                    "NBT_LIST_BOUNDS")
            return [self.payload(nested, depth+1) for _ in range(n)]
        if tag == 10:
            value = {}
            for _ in range(MAX_ITEMS):
                nested = self.num("B")
                if nested == 0: return value
                require(1 <= nested <= 12, "NBT_TAG_UNSUPPORTED")
                name = self.string()
                require(name not in value, "NBT_DUPLICATE_NAME")
                value[name] = self.payload(nested, depth+1)
            raise Refused("NBT_COMPOUND_TOO_LARGE")
        raise Refused("NBT_TAG_UNSUPPORTED")

    def document(self):
        require(self.num("B") == 10, "NBT_ROOT_NOT_COMPOUND")
        self.string()
        result = self.payload(10)
        require(self.i == len(self.data), "NBT_TRAILING_BYTES")
        return result


def chunk_from_region(blob: bytes):
    require(type(blob) is bytes and 8192 <= len(blob) <= MAX_REGION,
            "REGION_FILE_BOUNDS")
    # Fixed region r.0.0.mca, chunk (0,0); no path or caller-controlled index.
    entry = int.from_bytes(blob[0:4], "big")
    sector, count = entry >> 8, entry & 255
    require(sector >= 2 and count > 0 and sector*4096 < len(blob) and
            (sector+count)*4096 <= len(blob), "REGION_CHUNK_NOT_OWNED")
    start = sector*4096
    n = int.from_bytes(blob[start:start+4], "big")
    require(1 < n <= count*4096-4 and n <= MAX_CHUNK,
            "REGION_CHUNK_LENGTH_INVALID")
    # Only inline zlib Anvil: refuse external sidecars, other compressors,
    # header overlap, malformed stream and zip bombs.
    require(blob[start+4] == 2, "REGION_COMPRESSION_UNSUPPORTED")
    packed = blob[start+5:start+4+n]
    require(len(packed) == n-1, "REGION_TRUNCATED")
    try:
        inflater = zlib.decompressobj()
        decoded = inflater.decompress(packed, MAX_CHUNK+1)
        decoded += inflater.flush(MAX_CHUNK+1-len(decoded))
        require(inflater.eof and not inflater.unused_data and
                not inflater.unconsumed_tail and 0 < len(decoded) <= MAX_CHUNK,
                "REGION_DECOMPRESS_BOUNDS")
    except (zlib.error, ValueError):
        raise Refused("REGION_DECOMPRESS_BOUNDS") from None
    root = NBT(decoded).document()
    require(type(root) is dict and root.get("xPos") == 0 and root.get("zPos") == 0,
            "REGION_WRONG_CHUNK")
    return root


def block_at(root: dict, xyz: tuple[int, int, int]):
    x, y, z = xyz
    require(0 <= x <= 15 and 0 <= z <= 15 and y == 70,
            "FIXTURE_COORDINATE_DRIFT")
    sections = root.get("sections")
    require(type(sections) is list and len(sections) <= 32, "SECTION_LIST_INVALID")
    section_y = y // 16
    selected = [v for v in sections if type(v) is dict and v.get("Y") == section_y]
    require(len(selected) == 1, "SECTION_ID_AMBIGUOUS")
    states = selected[0].get("block_states")
    require(type(states) is dict and type(states.get("palette")) is list,
            "BLOCK_PALETTE_MISSING")
    palette = states["palette"]
    require(1 <= len(palette) <= 4096 and all(type(p) is dict and
            type(p.get("Name")) is str and
            p["Name"].startswith("minecraft:") for p in palette),
            "BLOCK_PALETTE_INVALID")
    if len(palette) == 1:
        # A uniform section has no palette data. Nonempty data for uniform
        # sections is unusual, but must still contain valid zero indices.
        data = states.get("data", [])
    else:
        data = states.get("data")
        require(type(data) is list and data, "BLOCK_DATA_REQUIRED")
    require(type(data) is list and len(data) <= 1024 and
            all(type(v) is int and -(1<<63) <= v < (1<<63) for v in data),
            "BLOCK_DATA_INVALID")
    if not data:
        require(len(palette) == 1, "BLOCK_DATA_REQUIRED")
        return palette[0]["Name"]
    bits = max(4, math.ceil(math.log2(len(palette))))
    per_long = 64 // bits
    idx = ((y & 15) << 8) | (z << 4) | x
    position, shift = divmod(idx, per_long)
    require(position < len(data), "BLOCK_DATA_TRUNCATED")
    number = ((data[position] & ((1<<64)-1)) >> (shift*bits)) & ((1<<bits)-1)
    require(number < len(palette), "BLOCK_PALETTE_INDEX_INVALID")
    return palette[number]["Name"]


def inspect(region_bytes: bytes, stage: str) -> dict:
    require(stage in EXPECTED, "STAGE_NOT_ADMITTED")
    root = chunk_from_region(region_bytes)
    actual = tuple(block_at(root, c) for c in COORDINATES)
    require(actual == EXPECTED[stage], "SERVER_BLOCK_CONSEQUENCE_ABSENT")
    return {
        "schema": SCHEMA, "classification": "UNTRUSTED_REGION_BYTES_DECODED_ONLY",
        "stage": stage, "region_sha256": hashlib.sha256(region_bytes).hexdigest(),
        "coordinates": [list(c) for c in COORDINATES],
        "block_state_expectations_matched": True,
        "native_guest_server_owned_bytes_proven": False,
        "server_quiescence_proven": False,
        "backend_independent_world_oracle_pass": False,
        "collage_mutation_authorized": False,
        "physical_true_nas_apply": "HOLD",
    }


def compare(candidate: bytes, rollback: bytes) -> dict:
    require(type(candidate) is bytes and type(rollback) is bytes and
            8192 <= len(candidate) <= MAX_REGION and
            8192 <= len(rollback) <= MAX_REGION, "REGION_FILE_BOUNDS")
    require(candidate != rollback, "CANDIDATE_ROLLBACK_SAME_REGION_REPLAY")
    c, r = inspect(candidate, "candidate"), inspect(rollback, "rollback")
    return {
        "schema": SCHEMA,
        "classification": "SOURCE_ONLY_DUAL_ANVIL_BLOCK_DECODER",
        "candidate_region_sha256": c["region_sha256"],
        "rollback_region_sha256": r["region_sha256"],
        "block_states_differ_exactly_as_expected": True,
        "server_origin_authenticated": False,
        "world_quiescence_observed": False,
        "backend_independent_world_oracle_pass": False,
        "next_gate": "LIVE_QUIESCED_GUEST_FIXED_REGION_DOWNLOAD_AND_PREACTION_CONTROL",
        "physical_true_nas_apply": "HOLD",
    }
