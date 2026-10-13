"""Public synthetic LAN/WAN control-protocol and DNS confinement oracle.

Independently authored; concept references Mullvad docs/security.md pinned in
README. This is a *gateway-specific research hypothesis*, not a packet filter.
Packets use documentation-only IP ranges and synthetic interface roles.
"""
from dataclasses import dataclass
from ipaddress import ip_address, ip_network


@dataclass(frozen=True)
class Packet:
    family: int
    direction: str  # in, out, forward relative to gateway
    side: str       # lan, wan, tunnel; must be from trusted interface identity
    proto: str      # udp, tcp, icmpv6
    src: str
    dst: str
    sport: int = 0
    dport: int = 0
    icmp_type: int = -1
    icmp_code: int = -1


@dataclass(frozen=True)
class Policy:
    lan_dhcp_server: bool = False
    wan_dhcp_client: bool = False
    wan_router_advertisements: bool = False
    lan_router_advertisements: bool = False
    allow_lan_neighbor_discovery: bool = True
    allow_wan_neighbor_discovery: bool = True


def _ip_ok(p: Packet) -> bool:
    try:
        return (ip_address(p.src).version == p.family
                and ip_address(p.dst).version == p.family
                and p.family in (4, 6))
    except ValueError:
        return False


def allow_control(p: Packet, policy: Policy) -> bool:
    """Allow minimal local *control-plane* traffic, never routed traffic."""
    if not _ip_ok(p) or p.direction not in ("in", "out") or p.side not in ("lan", "wan"):
        return False
    if p.family == 4 and p.proto == "udp":
        if p.side == "wan" and policy.wan_dhcp_client:
            # DHCP client initial discover/broadcast and server return.
            return ((p.direction == "out" and p.sport == 68 and p.dport == 67
                     and p.dst == "255.255.255.255" and
                     ip_address(p.src) in ip_network("0.0.0.0/0"))
                    or (p.direction == "in" and p.sport == 67 and p.dport == 68))
        if p.side == "lan" and policy.lan_dhcp_server:
            return ((p.direction == "in" and p.sport == 68 and p.dport == 67)
                    or (p.direction == "out" and p.sport == 67 and p.dport == 68))
        return False
    if p.family == 6 and p.proto == "udp":
        if p.side == "wan" and policy.wan_dhcp_client:
            return ((p.direction == "out" and p.sport == 546 and p.dport == 547
                     and p.src.lower().startswith("fe80:")
                     and ip_address(p.dst) in ip_network("ff02::1:2/128"))
                    or (p.direction == "in" and p.sport == 547 and p.dport == 546
                        and ip_address(p.src) in ip_network("fe80::/10")))
        if p.side == "lan" and policy.lan_dhcp_server:
            return ((p.direction == "in" and p.sport == 546 and p.dport == 547)
                    or (p.direction == "out" and p.sport == 547 and p.dport == 546))
        return False
    if p.family != 6 or p.proto != "icmpv6" or p.icmp_code != 0:
        return False

    src, dst = ip_address(p.src), ip_address(p.dst)
    if not (policy.allow_lan_neighbor_discovery if p.side == "lan"
            else policy.allow_wan_neighbor_discovery):
        return False

    link_src = src in ip_network("fe80::/10")
    link_dst = dst in ip_network("fe80::/10")
    solicited_dst = dst in ip_network("ff02::1:ff00:0/104")

    # Router advertisements must not be trusted on a LAN client-facing port.
    if p.icmp_type == 134:  # RA inbound from WAN only if explicitly admitted
        return (p.side == "wan" and p.direction == "in"
                and policy.wan_router_advertisements and link_src
                and (link_dst or dst == ip_address("ff02::1")))
    if p.icmp_type == 133:  # RS WAN client out or LAN server in
        return ((p.side == "wan" and p.direction == "out" and
                 policy.wan_router_advertisements and dst == ip_address("ff02::2"))
                or (p.side == "lan" and p.direction == "in"
                    and policy.lan_router_advertisements and link_src
                    and dst == ip_address("ff02::2")))
    if p.icmp_type == 135:  # NS on-link only, no forwarding
        return (p.direction in ("in", "out") and
                (link_src or src == ip_address("::"))
                and (link_dst or solicited_dst))
    if p.icmp_type == 136:  # NA on-link only
        return (link_src and (link_dst or dst == ip_address("ff02::1")))
    return False


def allow_dns_egress(*, phase: str, interface: str, family: int,
                     proto: str, dport: int, resolver_authorized: bool) -> bool:
    """Model-only intent for upstream DNS: never resolve plaintext via WAN.

    Note: DoH (443) and DoQ (853) require separately justified network policy;
    port-53 confinement alone does not prevent encrypted-DNS evasion.
    """
    return bool(
        phase == "connected"
        and interface == "tunnel"
        and family in (4, 6)
        and proto in ("udp", "tcp")
        and dport == 53
        and resolver_authorized
    )
