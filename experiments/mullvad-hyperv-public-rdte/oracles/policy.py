"""Pure, independently authored VPN gateway policy-oracle model.

Public synthetic examples ONLY. This module neither reads actual tunnel state
nor writes firewall/network state. All receipt booleans are *untrusted* unless
issued by an independently qualified observer in a real implementation.
"""
from dataclasses import dataclass
from ipaddress import ip_address

STATES = frozenset({"boot", "connecting", "connected", "switching", "error", "recovery", "revoked"})


@dataclass(frozen=True)
class Receipt:
    policy_epoch: int
    tunnel_epoch: int
    route_epoch: int
    admission_epoch: int
    issued_under_admission_epoch: int
    kernel_ack: bool
    policy_readback: bool
    tunnel_readback: bool
    route_readback: bool
    outside_ipv4_blocked: bool
    outside_ipv6_blocked: bool
    guard_installed: bool


@dataclass(frozen=True)
class State:
    phase: str
    policy_epoch: int
    tunnel_epoch: int
    route_epoch: int
    admission_epoch: int
    admitted: bool


def eligible_for_user_egress(state: State, receipt: Receipt | None) -> bool:
    """Model contract: all current independent observations must agree."""
    if state.phase != "connected" or not state.admitted or receipt is None:
        return False
    return (
        state.policy_epoch > 0
        and state.tunnel_epoch > 0
        and state.route_epoch > 0
        and state.admission_epoch > 0
        and receipt.policy_epoch == state.policy_epoch
        and receipt.tunnel_epoch == state.tunnel_epoch
        and receipt.route_epoch == state.route_epoch
        and receipt.admission_epoch == state.admission_epoch
        and receipt.issued_under_admission_epoch == state.admission_epoch
        and receipt.kernel_ack
        and receipt.policy_readback
        and receipt.tunnel_readback
        and receipt.route_readback
        and receipt.outside_ipv4_blocked
        and receipt.outside_ipv6_blocked
        and receipt.guard_installed
    )


@dataclass(frozen=True)
class OuterPacket:
    proto: str
    host: str
    port: int
    origin: str
    mark: int


@dataclass(frozen=True)
class FirstHop:
    host: str
    port: int
    mark: int
    policy_epoch: int
    control_epoch: int
    authorized: bool


def allow_plain_wan(state: State, packet: OuterPacket, permitted: FirstHop | None) -> bool:
    """Allow *only* explicit current-generation WireGuard first-hop transport.

    User-egress admission is intentionally NOT required for this path: the
    handshake must work while the gateway is still connecting. This separate
    minimal control permission is bound to both the policy and control epochs,
    and is invalidated on a transition/revocation. Source/origin/mark identity
    requires independently tested real-kernel enforcement.
    """
    if permitted is None:
        return False
    try:
        relay = ip_address(permitted.host)
        candidate = ip_address(packet.host)
    except (ValueError, TypeError):
        return False  # no hostnames, unknown or malformed peer IPs
    if relay.is_unspecified or relay.is_loopback or relay.is_multicast or relay.is_link_local:
        return False
    if not (type(permitted.port) is int and 1 <= permitted.port <= 65535):
        return False
    if not (type(permitted.mark) is int and 1 <= permitted.mark < (1 << 32)):
        return False
    return bool(
        state.phase in ("connecting", "connected")
        and permitted.authorized
        and state.policy_epoch > 0
        and state.admission_epoch > 0
        and permitted.policy_epoch == state.policy_epoch
        and permitted.control_epoch == state.admission_epoch
        and packet.proto == "udp"
        and candidate == relay
        and packet.port == permitted.port
        and packet.origin == "privileged-tunnel-worker"
        and packet.mark == permitted.mark
    )


def safe_transition(state: State, new_phase: str) -> State:
    """Invalidate admission on every transition except explicit new verify.

    An external actor must acquire *new* receipts before re-admitting.
    """
    if new_phase not in STATES:
        raise ValueError("unknown phase: fail closed")
    if new_phase == "connected":
        raise ValueError("cannot jump to connected without verify and new admission")
    return State(new_phase, state.policy_epoch, state.tunnel_epoch,
                 state.route_epoch, state.admission_epoch + 1, False)
