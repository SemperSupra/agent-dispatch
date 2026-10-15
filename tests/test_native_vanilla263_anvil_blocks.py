"""Synthetic G4 Anvil block-state decoder tests; never a live guest proof."""
from __future__ import annotations

import math
import struct
import unittest
import zlib

from scripts.qualify_native_vanilla263_anvil_blocks import Refused, compare, inspect

PALETTE = ("minecraft:redstone_block", "minecraft:air",
           "minecraft:sea_lantern", "minecraft:iron_bars", "minecraft:black_concrete")


def nbt_string(s):
    b = s.encode()
    return struct.pack(">H", len(b)) + b


def tag(number, name, payload):
    return bytes((number,)) + nbt_string(name) + payload


def compound(*children):
    return b"".join(children) + b"\x00"


def build(stage="candidate", *, x_pos=0, z_pos=0, overrides=None):
    positions = {((70 & 15) << 8) | (z << 4) | x: value
                 for (x, z, value) in (
                   (0, 0, 0), (2, 0, 1 if stage == "candidate" else 3),
                   (1, 1, 2 if stage == "candidate" else 4))}
    positions.update(overrides or {})
    bits, per_long = max(4, math.ceil(math.log2(len(PALETTE)))), 16
    # Default air; section 4 consists of exactly 4096 block indices.
    idxs = [positions.get(i, 1) for i in range(4096)]
    longs = []
    for block in range(0, 4096, per_long):
        value = sum(idxs[block + i] << (bits*i)
                    for i in range(per_long))
        if value >= 1 << 63:
            value -= 1 << 64
        longs.append(value)
    pal = b"".join(compound(tag(8, "Name", nbt_string(n))) for n in PALETTE)
    states = compound(
        tag(9, "palette", b"\x0a" + struct.pack(">i", len(PALETTE)) + pal),
        tag(12, "data", struct.pack(">i", len(longs)) +
            b"".join(struct.pack(">q", n) for n in longs)),
    )
    sections = compound(
        tag(1, "Y", struct.pack(">b", 4)),
        tag(10, "block_states", states),
    )
    root = compound(
        tag(3, "xPos", struct.pack(">i", x_pos)),
        tag(3, "zPos", struct.pack(">i", z_pos)),
        tag(9, "sections", b"\x0a" + struct.pack(">i", 1) + sections),
    )
    doc = b"\x0a" + nbt_string("") + root
    packed = zlib.compress(doc, 9)
    count = max(1, math.ceil((len(packed) + 5) / 4096))
    region = bytearray((2 + count) * 4096)
    region[0:4] = ((2 << 8) | count).to_bytes(4, "big")
    region[2*4096:2*4096+4] = (1+len(packed)).to_bytes(4, "big")
    region[2*4096+4] = 2
    region[2*4096+5:2*4096+5+len(packed)] = packed
    return bytes(region)


class BlockRegionTests(unittest.TestCase):
    def test_candidate_rollback_differ_source_only(self):
        result = compare(build("candidate"), build("rollback"))
        self.assertEqual(result["classification"],
                         "SOURCE_ONLY_DUAL_ANVIL_BLOCK_DECODER")
        self.assertFalse(result["server_origin_authenticated"])
        self.assertFalse(result["backend_independent_world_oracle_pass"])
        self.assertEqual(result["physical_true_nas_apply"], "HOLD")

    def test_individual_stages_not_backend_proof(self):
        for stage in ("candidate", "rollback"):
            result = inspect(build(stage), stage)
            self.assertTrue(result["block_state_expectations_matched"])
            self.assertFalse(result["native_guest_server_owned_bytes_proven"])
            self.assertFalse(result["server_quiescence_proven"])
            self.assertFalse(result["backend_independent_world_oracle_pass"])

    def reject(self, blob, stage, code):
        with self.assertRaises(Refused) as ex:
            inspect(blob, stage)
        self.assertEqual(str(ex.exception), code)

    def test_wrong_stage_and_replayed_same_region(self):
        self.reject(build(), "rollback", "SERVER_BLOCK_CONSEQUENCE_ABSENT")
        self.reject(build(), "unknown", "STAGE_NOT_ADMITTED")
        with self.assertRaisesRegex(Refused, "SAME_REGION_REPLAY"):
            compare(build(), build())

    def test_wrong_or_stale_placed_core_negative(self):
        idx = ((70 & 15) << 8) | (0 << 4) | 0
        self.reject(build(overrides={idx: 1}), "candidate",
                    "SERVER_BLOCK_CONSEQUENCE_ABSENT")

    def test_wrong_effect_negative(self):
        access_idx = ((70 & 15) << 8) | (0 << 4) | 2
        self.reject(build(overrides={access_idx: 3}), "candidate",
                    "SERVER_BLOCK_CONSEQUENCE_ABSENT")

    def test_wrong_chunk_and_dimension_not_admitted(self):
        self.reject(build(x_pos=1), "candidate", "REGION_WRONG_CHUNK")
        self.reject(build(z_pos=-1), "candidate", "REGION_WRONG_CHUNK")

    def test_truncated_or_empty_region(self):
        self.reject(b"", "candidate", "REGION_FILE_BOUNDS")
        self.reject(build()[:8191], "candidate", "REGION_FILE_BOUNDS")

    def test_corrupted_header_and_external_compression(self):
        blob = bytearray(build())
        blob[0:4] = b"\x00\x00\x00\x00"
        self.reject(bytes(blob), "candidate", "REGION_CHUNK_NOT_OWNED")
        blob = bytearray(build())
        blob[8192+4] = 0x82
        self.reject(bytes(blob), "candidate", "REGION_COMPRESSION_UNSUPPORTED")
        blob = bytearray(build())
        blob[8192:8196] = (99999999).to_bytes(4, "big")
        self.reject(bytes(blob), "candidate", "REGION_CHUNK_LENGTH_INVALID")

    def test_bad_decompression_rejected(self):
        blob = bytearray(build())
        blob[8192+5:8192+9] = b"xxxx"
        self.reject(bytes(blob), "candidate", "REGION_DECOMPRESS_BOUNDS")

    def test_reject_foreign_or_unqualified_blobs(self):
        with self.assertRaisesRegex(Refused, "REGION_FILE_BOUNDS"):
            compare(build(), b"caller-supplied-block-list")
        self.assertNotIn("native_guest_backend_independent_oracle_qualified",
                         inspect(build(), "candidate"))


if __name__ == "__main__":
    unittest.main()
