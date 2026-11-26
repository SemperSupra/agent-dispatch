"""Adversarial unit tests for the independent WAN-side ingress & reverse-path-drop oracle."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tools.netns_udp_witness import (
    format_reply,
    parse_probe_packet,
    verify_blocked_oracle,
)


class WanIngressOracleTests(unittest.TestCase):
    def test_parse_and_format_probe_nonce(self):
        self.assertEqual(parse_probe_packet(b"RDTE_TEST_ONLY_01"), "default")
        self.assertEqual(parse_probe_packet(b"RDTE_TEST_ONLY_01:blk-4-42001"), "blk-4-42001")
        self.assertIsNone(parse_probe_packet(b"WRONG_PAYLOAD"))
        self.assertIsNone(parse_probe_packet(b"RDTE_TEST_ONLY_01:bad nonce spaces"))
        self.assertEqual(format_reply("default"), b"RDTE_ACK_ONLY_01")
        self.assertEqual(format_reply("blk-6-42002"), b"RDTE_ACK_ONLY_01:blk-6-42002")

    def test_verify_blocked_oracle_passes_only_when_timeout_and_zero_wan_ingress(self):
        before = {"total_ingress": 2, "by_key": {"v4:42001": 1, "v6:42001": 1}, "nonces": []}
        after = {"total_ingress": 2, "by_key": {"v4:42001": 1, "v6:42001": 1}, "nonces": []}
        ok, reason = verify_blocked_oracle(
            4, before, after, family=4, port=42001, nonce="blk-4-42001"
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "ZERO_WAN_INGRESS_VERIFIED")

    def test_reverse_path_drop_mutant_is_rejected_despite_client_timeout(self):
        # Outbound packet leaked to WAN (ingress counter incremented from 1 to 2),
        # while reply was dropped so client returned timeout (rc=4).
        before = {"total_ingress": 1, "by_key": {"v4:42001": 1}, "nonces": []}
        after = {
            "total_ingress": 2,
            "by_key": {"v4:42001": 2},
            "nonces": ["v4:42001:mutant-revdrop-4"],
        }
        ok, reason = verify_blocked_oracle(
            4, before, after, family=4, port=42001, nonce="mutant-revdrop-4"
        )
        self.assertFalse(ok)
        self.assertIn("ONE_WAY_WAN_INGRESS_LEAK_DETECTED", reason)

    def test_roundtrip_escape_and_unexpected_probe_rc_rejected(self):
        state = {"total_ingress": 1, "by_key": {"v6:42002": 1}, "nonces": []}
        ok_rt, reason_rt = verify_blocked_oracle(0, state, state, family=6, port=42002)
        self.assertFalse(ok_rt)
        self.assertEqual(reason_rt, "ROUNDTRIP_PLAINTEXT_ESCAPE")

        ok_err, reason_err = verify_blocked_oracle(5, state, state, family=6, port=42002)
        self.assertFalse(ok_err)
        self.assertEqual(reason_err, "UNEXPECTED_PROBE_RC_5")


if __name__ == "__main__":
    unittest.main()
