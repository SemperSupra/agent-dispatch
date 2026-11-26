#!/usr/bin/env python3
"""Public synthetic UDP witness, Linux netns-only; no Mullvad or operational data.

Server: records independent WAN-side ingress packet counts and nonces before
sending any reply, proving one-way outbound leak detection even when replies
are dropped on the reverse path.
Probe: exit 0 only for matching response, 4 on timeout, 5 on other error.
No real provider calls, DNS or external connectivity.
"""
import argparse
import json
import os
from pathlib import Path
import re
import select
import socket
import tempfile

PORTS = (42001, 42002)
PROBE = b"RDTE_TEST_ONLY_01"
REPLY = b"RDTE_ACK_ONLY_01"
V4 = "198.51.100.2"
V6 = "2001:db8:2::2"
NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def parse_probe_packet(packet: bytes) -> str | None:
    if packet == PROBE:
        return "default"
    prefix = PROBE + b":"
    if packet.startswith(prefix):
        try:
            nonce = packet[len(prefix):].decode("ascii")
        except UnicodeDecodeError:
            return None
        if NONCE_RE.fullmatch(nonce):
            return nonce
    return None


def format_reply(nonce: str) -> bytes:
    if nonce == "default":
        return REPLY
    return REPLY + b":" + nonce.encode("ascii")


def write_ingress_ledger(path: str | None, state: dict) -> None:
    if not path:
        return
    target = Path(path)
    fd, tmp_name = tempfile.mkstemp(prefix=".wan-ingress-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
    except OSError:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def server(ingress_log: str | None = None):
    socks = []
    meta = {}
    state = {
        "total_ingress": 0,
        "by_key": {},
        "nonces": [],
    }
    write_ingress_ledger(ingress_log, state)
    for family, address, fam_label in (
        (socket.AF_INET, V4, "4"),
        (socket.AF_INET6, V6, "6"),
    ):
        for port in PORTS:
            s = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((address, port))
            socks.append(s)
            meta[s.fileno()] = f"v{fam_label}:{port}"
    try:
        while True:
            ready, _, _ = select.select(socks, [], [], 1.0)
            for s in ready:
                packet, client = s.recvfrom(256)
                nonce = parse_probe_packet(packet)
                if nonce is not None:
                    key = meta[s.fileno()]
                    state["total_ingress"] += 1
                    state["by_key"][key] = state["by_key"].get(key, 0) + 1
                    if len(state["nonces"]) < 512:
                        state["nonces"].append(f"{key}:{nonce}")
                    write_ingress_ledger(ingress_log, state)
                    s.sendto(format_reply(nonce), client)
    finally:
        for s in socks:
            s.close()


def probe(ip_version, port, nonce: str | None = None):
    if nonce is not None and not NONCE_RE.fullmatch(nonce):
        return 2
    address = V4 if ip_version == 4 else V6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    payload = PROBE if not nonce else (PROBE + b":" + nonce.encode("ascii"))
    expected = REPLY if not nonce else (REPLY + b":" + nonce.encode("ascii"))
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(0.7)
    try:
        s.sendto(payload, (address, port))
        data, _ = s.recvfrom(256)
        if data != expected:
            return 5
        return 0
    except socket.timeout:
        return 4
    except OSError:
        return 5
    finally:
        s.close()


def verify_blocked_oracle(
    probe_rc: int,
    before_state: dict,
    after_state: dict,
    *,
    family: int,
    port: int,
    nonce: str | None = None,
) -> tuple[bool, str]:
    """Require BOTH client receive timeout (rc==4) AND zero WAN ingress delta."""
    if probe_rc == 0:
        return False, "ROUNDTRIP_PLAINTEXT_ESCAPE"
    if probe_rc != 4:
        return False, f"UNEXPECTED_PROBE_RC_{probe_rc}"
    key = f"v{family}:{port}"
    before_count = int(before_state.get("by_key", {}).get(key, 0))
    after_count = int(after_state.get("by_key", {}).get(key, 0))
    if after_count != before_count:
        return False, f"ONE_WAY_WAN_INGRESS_LEAK_DETECTED:{key}:delta={after_count - before_count}"
    if nonce and f"{key}:{nonce}" in after_state.get("nonces", []):
        return False, f"ONE_WAY_WAN_NONCE_OBSERVED:{key}:{nonce}"
    return True, "ZERO_WAN_INGRESS_VERIFIED"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "probe"))
    parser.add_argument("--family", type=int, choices=(4, 6))
    parser.add_argument("--port", type=int, choices=PORTS)
    parser.add_argument("--nonce", type=str, default=None)
    parser.add_argument("--ingress-log", type=str, default=None)
    args = parser.parse_args()
    if args.mode == "server":
        if args.family is not None or args.port is not None or args.nonce is not None:
            raise SystemExit(2)
        server(args.ingress_log)
    else:
        if args.family is None or args.port is None or args.ingress_log is not None:
            raise SystemExit(2)
        raise SystemExit(probe(args.family, args.port, args.nonce))


if __name__ == "__main__":
    main()
