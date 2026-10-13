"""Synthetic adversarial policy qualification. No network operations."""
import dataclasses
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from oracles.policy import (
    State, Receipt, OuterPacket, FirstHop, eligible_for_user_egress,
    allow_plain_wan, safe_transition,
)


class SafetyOracleTests(unittest.TestCase):
    def setUp(self):
        self.state = State("connected", 11, 19, 7, 5, True)
        self.receipt = Receipt(11, 19, 7, 5, 5, True, True, True, True, True, True, True)

    def test_positive_control_verified_connected(self):
        self.assertTrue(eligible_for_user_egress(self.state, self.receipt))

    def test_negative_control_missing_witness_rejected(self):
        self.assertFalse(eligible_for_user_egress(self.state, None))

    def test_all_fail_closed_phases(self):
        for phase in ("boot", "connecting", "switching", "error", "recovery", "revoked"):
            with self.subTest(phase=phase):
                self.assertFalse(eligible_for_user_egress(dataclasses.replace(self.state, phase=phase), self.receipt))

    def test_every_guard_or_observer_bit_individually_required(self):
        fields = ["kernel_ack", "policy_readback", "tunnel_readback", "route_readback",
                  "outside_ipv4_blocked", "outside_ipv6_blocked", "guard_installed"]
        for name in fields:
            with self.subTest(mutation=name):
                mutant = dataclasses.replace(self.receipt, **{name: False})
                self.assertFalse(eligible_for_user_egress(self.state, mutant))

    def test_all_epochs_and_revocation_must_match(self):
        for name in ("policy_epoch", "tunnel_epoch", "route_epoch", "admission_epoch"):
            with self.subTest(mutation=name):
                mutant = dataclasses.replace(self.receipt, **{name: getattr(self.receipt, name) - 1})
                self.assertFalse(eligible_for_user_egress(self.state, mutant))
        # Revoke -> reauthorize must invalidate a receipt from the prior admission.
        self.assertFalse(eligible_for_user_egress(self.state, dataclasses.replace(
            self.receipt, issued_under_admission_epoch=4)))
        self.assertFalse(eligible_for_user_egress(dataclasses.replace(self.state, admitted=False), self.receipt))

    def test_transition_requires_new_verification(self):
        for phase in ("boot", "connecting", "switching", "error", "recovery", "revoked"):
            next_state = safe_transition(self.state, phase)
            self.assertFalse(next_state.admitted)
            self.assertEqual(next_state.admission_epoch, self.state.admission_epoch + 1)
            self.assertFalse(eligible_for_user_egress(next_state, self.receipt))
        with self.assertRaises(ValueError):
            safe_transition(self.state, "connected")
        with self.assertRaises(ValueError):
            safe_transition(self.state, "unrecognized")

    def test_first_hop_scope_and_mutants(self):
        hop = FirstHop("198.51.100.7", 51820, 0x701, 11, 5, True)
        pkt = OuterPacket("udp", "198.51.100.7", 51820, "privileged-tunnel-worker", 0x701)
        self.assertTrue(allow_plain_wan(self.state, pkt, hop))
        for attr, value in [
            ("proto", "tcp"), ("host", "203.0.113.9"), ("port", 443),
            ("origin", "unprivileged-app"), ("mark", 0x702)]:
            with self.subTest(mutation=attr):
                self.assertFalse(allow_plain_wan(self.state, dataclasses.replace(pkt, **{attr: value}), hop))
        self.assertFalse(allow_plain_wan(self.state, pkt, None))
        # Bootstrapping the first hop must work before *user traffic* is admitted.
        connecting = dataclasses.replace(self.state, phase="connecting", admitted=False)
        self.assertTrue(allow_plain_wan(connecting, pkt, hop))
        self.assertFalse(eligible_for_user_egress(connecting, self.receipt))
        # Denying user egress does not implicitly revoke the narrowly scoped relay.
        self.assertTrue(allow_plain_wan(dataclasses.replace(self.state, admitted=False), pkt, hop))
        # But a policy/control epoch change or revocation immediately invalidates it.
        for attr, val in [("policy_epoch", 10), ("control_epoch", 4), ("authorized", False)]:
            with self.subTest(permit_mutant=attr):
                self.assertFalse(allow_plain_wan(self.state, pkt, dataclasses.replace(hop, **{attr: val})))
        transitioned = safe_transition(self.state, "connecting")
        self.assertFalse(allow_plain_wan(transitioned, pkt, hop))
        self.assertFalse(allow_plain_wan(dataclasses.replace(self.state, policy_epoch=12), pkt, hop))
        for phase in ("boot", "switching", "error", "recovery", "revoked"):
            self.assertFalse(allow_plain_wan(dataclasses.replace(self.state, phase=phase), pkt, hop))

    def test_zero_epoch_or_mark_not_trusted(self):
        for attr in ("policy_epoch", "tunnel_epoch", "route_epoch", "admission_epoch"):
            self.assertFalse(eligible_for_user_egress(dataclasses.replace(self.state, **{attr: 0}), self.receipt))
        hop = FirstHop("198.51.100.7", 51820, 0, 11, 5, True)
        pkt = OuterPacket("udp", hop.host, hop.port, "privileged-tunnel-worker", 0)
        self.assertFalse(allow_plain_wan(self.state, pkt, hop))


if __name__ == "__main__":
    unittest.main()
