#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "wrt3200acm_cloud_recovery.py"
spec = importlib.util.spec_from_file_location("wrt_recovery", SCRIPT)
mod = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(mod)

class RecoveryUnitTests(unittest.TestCase):
    def test_entropy(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.bin"
            p.write_bytes(bytes(range(256)) * 32)
            self.assertGreater(mod.entropy(p), 7.9)

    def test_magic_scan(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.bin"
            p.write_bytes(b"A" * 16 + b"hsqs" + b"B" * 16 + b"ThreadX")
            r = mod.magic_scan(p)
            self.assertEqual(r["squashfs-le"]["offsets"], [16])
            self.assertIn("text:ThreadX", r)

    def test_parse_host_commands_regex(self):
        sample = "#define HOSTCMD_CMD_FOO 0x1234\n#define HOSTCMD_CMD_BAR 0xabcd\n"
        got = mod.CMD_RE.findall(sample)
        self.assertEqual(got, [("HOSTCMD_CMD_FOO", "0x1234"), ("HOSTCMD_CMD_BAR", "0xabcd")])

    def test_structural_dispatch_scan(self):
        import json
        import struct
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            blob = root / "fw.bin"
            payload = bytearray(128)
            # Three 8-byte entries: cmd16 at +0, handler32 at +4.
            for i, (cmd, ptr) in enumerate([(0x1100, 0x20), (0x1101, 0x41), (0x1121, 0x60)]):
                off = i * 8
                struct.pack_into("<H", payload, off, cmd)
                struct.pack_into("<I", payload, off + 4, ptr)
            record = struct.pack("<IIII", 1, 0, len(payload) + 4, 0) + bytes(payload) + b"CHK!"
            data = record + struct.pack("<IIII", 4, 0, 0, 0)
            blob.write_bytes(data)
            rmap = mod.marvell_record_map(blob)
            commands = [
                {"name":"HOSTCMD_CMD_BSS_START","value":0x1100},
                {"name":"HOSTCMD_CMD_AP_BEACON","value":0x1101},
                {"name":"HOSTCMD_CMD_SET_SWITCH_CHANNEL","value":0x1121},
            ]
            result = mod.structural_dispatch_scan(blob, commands, rmap, root)
            self.assertGreaterEqual(len(result["table_candidates"]), 1)
            top = result["table_candidates"][0]
            self.assertGreaterEqual(top["distinct_commands"], 3)
            self.assertEqual(top["entry_size"], 8)

    def test_marvell_record_map(self):
        import struct
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            blob = root / "fw.bin"
            record = struct.pack("<IIII", 1, 0x1000, 8, 0x12345678) + b"ABCD" + b"WXYZ"
            end = struct.pack("<IIII", 4, 0, 0, 0)
            blob.write_bytes(record + end)
            r = mod.marvell_record_map(blob)
            self.assertTrue(r["valid_prefix"])
            self.assertEqual(r["termination"], "type4-end")
            self.assertEqual(r["records"][0]["load_address"], 0x1000)
            self.assertEqual(r["records"][0]["payload_size"], 4)
            self.assertEqual(r["records"][0]["trailer_hex"], b"WXYZ".hex())

    def test_command_word_scan(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            blob = root / "f.bin"
            blob.write_bytes(b"\x00\x00\x34\x12\x00\x00\x12\x34")
            commands = [{"name":"HOSTCMD_CMD_FOO","value":0x1234,"hex":"0x1234"}]
            r = mod.scan_command_words(blob, commands, root)
            self.assertIn(2, r["rows"][0]["little_endian_offsets"])
            self.assertIn(6, r["rows"][0]["big_endian_offsets"])

if __name__ == "__main__":
    unittest.main()
