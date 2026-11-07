"""Synthetic gateway-specific DHCP/NDP/DNS authorization: positive and red mutants.

Use documentation-only addresses. No privilege, sockets, account, packet capture,
or provider API calls. Role semantics are hypothetical pending native kernel tests.
"""
import dataclasses
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from oracles.linklocal import Packet, Policy, allow_control, allow_dns_egress


class LinkLocalPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy(wan_dhcp_client=True, lan_dhcp_server=True,
                             wan_router_advertisements=True,
                             lan_router_advertisements=True)

    def test_client_dhcp_ipv4_positive_and_mutants(self):
        p = Packet(4, "out", "wan", "udp", "0.0.0.0", "255.255.255.255", 68, 67)
        self.assertTrue(allow_control(p, self.policy))
        for attr, value in (("side", "lan"), ("direction", "forward"),
                            ("dport", 53), ("proto", "tcp"),
                            ("dst", "198.51.100.1"), ("family", 6)):
            with self.subTest(attr=attr):
                self.assertFalse(allow_control(dataclasses.replace(p, **{attr: value}), self.policy))
        self.assertFalse(allow_control(p, dataclasses.replace(self.policy, wan_dhcp_client=False)))

    def test_server_dhcp_ipv4_is_lan_only(self):
        p = Packet(4, "in", "lan", "udp", "0.0.0.0", "255.255.255.255", 68, 67)
        self.assertTrue(allow_control(p, self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, side="wan"), self.policy))
        self.assertFalse(allow_control(p, dataclasses.replace(self.policy, lan_dhcp_server=False)))

    def test_dhcpv6_client_link_local(self):
        p = Packet(6, "out", "wan", "udp", "fe90::123", "ff02::1:2", 546, 547)
        self.assertTrue(allow_control(p, self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, src="2001:db8::123"), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, dport=53), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, side="lan"), self.policy))

    def test_rogue_router_advertisements_rejected_on_lan(self):
        p = Packet(6, "in", "wan", "icmpv6", "fe80::1", "ff02::1", icmp_type=134, icmp_code=0)
        self.assertTrue(allow_control(p, self.policy))
        for mutation in (dict(side="lan"), dict(src="2001:db8::1"),
                         dict(icmp_code=1), dict(direction="forward"),
                         dict(dst="2001:db8::5")):
            with self.subTest(mutation=mutation):
                self.assertFalse(allow_control(dataclasses.replace(p, **mutation), self.policy))
        self.assertFalse(allow_control(p, dataclasses.replace(self.policy, wan_router_advertisements=False)))

    def test_router_solicitation_role_is_explicit(self):
        p = Packet(6, "out", "wan", "icmpv6", "fe80::2", "ff02::2", icmp_type=133, icmp_code=0)
        self.assertTrue(allow_control(p, self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, direction="forward"), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, dst="ff02::1"), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, side="lan"), self.policy))

    def test_ndp_neighbor_solicitation_only_link_scope(self):
        p = Packet(6, "out", "lan", "icmpv6", "fe80::2",
                   "ff02::1:ff00:1234", icmp_type=135, icmp_code=0)
        self.assertTrue(allow_control(p, self.policy))
        # Duplicate Address Detection can use :: as source.
        self.assertTrue(allow_control(dataclasses.replace(p, src="::"), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, dst="2001:db8::5"), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, direction="forward"), self.policy))
        self.assertFalse(allow_control(p, dataclasses.replace(self.policy, allow_lan_neighbor_discovery=False)))

    def test_ndp_neighbor_advertisement_link_scope(self):
        p = Packet(6, "in", "wan", "icmpv6", "fe80::1",
                   "ff02::1", icmp_type=136, icmp_code=0)
        self.assertTrue(allow_control(p, self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, src="2001:db8::1"), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, icmp_type=137), self.policy))
        self.assertFalse(allow_control(p, dataclasses.replace(self.policy, allow_wan_neighbor_discovery=False)))

    def test_no_forwarded_link_local_controls(self):
        for proto, family in (("udp", 4), ("udp", 6), ("icmpv6", 6)):
            p = Packet(family, "forward", "wan", proto,
                       "fe80::1" if family == 6 else "0.0.0.0",
                       "ff02::1" if family == 6 else "255.255.255.255",
                       546 if family == 6 else 68,
                       547 if family == 6 else 67,
                       135 if proto == "icmpv6" else -1,
                       0 if proto == "icmpv6" else -1)
            self.assertFalse(allow_control(p, self.policy))

    def test_bad_address_family_and_interface_fail_closed(self):
        p = Packet(6, "in", "lan", "icmpv6", "not-an-address",
                   "ff02::1", icmp_type=134, icmp_code=0)
        self.assertFalse(allow_control(p, self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, src="198.51.100.1"), self.policy))
        self.assertFalse(allow_control(dataclasses.replace(p, src="fe80::1", side="tunnel"), self.policy))

    def test_dns_tunnel_only_both_families(self):
        for family in (4, 6):
            for proto in ("tcp", "udp"):
                self.assertTrue(allow_dns_egress(
                    phase="connected", interface="tunnel", family=family,
                    proto=proto, dport=53, resolver_authorized=True))
        for mutation in (dict(phase="connecting"), dict(phase="revoked"),
                         dict(interface="wan"), dict(interface="lan"),
                         dict(resolver_authorized=False), dict(dport=853),
                         dict(proto="icmpv6"), dict(family=7)):
            kwargs = dict(phase="connected", interface="tunnel", family=6,
                          proto="udp", dport=53, resolver_authorized=True)
            kwargs.update(mutation)
            with self.subTest(mutation=mutation):
                self.assertFalse(allow_dns_egress(**kwargs))

    def test_default_policy_does_not_admit_wan_ra_or_dhcp(self):
        default = Policy()
        packets = [
            Packet(6, "in", "wan", "icmpv6", "fe80::1", "ff02::1", icmp_type=134, icmp_code=0),
            Packet(4, "out", "wan", "udp", "0.0.0.0", "255.255.255.255", 68, 67),
            Packet(6, "out", "wan", "udp", "fe80::1", "ff02::1:2", 546, 547),
        ]
        for p in packets:
            self.assertFalse(allow_control(p, default))


if __name__ == "__main__":
    unittest.main()
