"""Read-only NetVSC channel parser regression fixtures; no actual NIC changes."""
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tools.capabilities import parse_current_channels


class NetVscInventoryTests(unittest.TestCase):
    def test_distinguishes_preset_maximum_from_current(self):
        output = """Channel parameters for eth0:
Pre-set maximums:
RX: 64
TX: 64
Other: 0
Combined: 64
Current hardware settings:
RX: 0
TX: 0
Other: 0
Combined: 8
"""
        self.assertEqual(parse_current_channels(output), {"rx": 0, "tx": 0, "combined": 8})

    def test_missing_current_section_never_assumes_maximum(self):
        self.assertIsNone(parse_current_channels("Pre-set maximums:\nCombined: 64\n"))

    def test_invalid_channel_fields_and_out_of_bounds_refused(self):
        self.assertIsNone(parse_current_channels("Current hardware settings:\nCombined: -1\n"))
        self.assertIsNone(parse_current_channels("Current hardware settings:\nCombined: 999999999\n"))
        self.assertIsNone(parse_current_channels("Current hardware settings:\nCombined: secret\n"))

    def test_receive_only_channel_count(self):
        self.assertEqual(parse_current_channels(
            "Current hardware settings:\nRX: 2\nTX: 1\n"),
            {"rx": 2, "tx": 1})


if __name__ == "__main__":
    unittest.main()
