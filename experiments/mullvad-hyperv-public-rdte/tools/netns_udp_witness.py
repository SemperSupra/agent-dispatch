#!/usr/bin/env python3
"""Public synthetic UDP witness, Linux netns-only; no Mullvad or operational data.

Server: reply only to an exact fixed public test payload on test ports.
Probe: exit 0 only for matching response, 4 on timeout, 5 on other error.
No real provider calls, DNS or external connectivity.
"""
import argparse
import select
import socket
import sys
import time

PORTS = (42001, 42002)
PROBE = b"RDTE_TEST_ONLY_01"
REPLY = b"RDTE_ACK_ONLY_01"
V4 = "198.51.100.2"
V6 = "2001:db8:2::2"


def server():
    socks = []
    for family, address in ((socket.AF_INET, V4), (socket.AF_INET6, V6)):
        for port in PORTS:
            s = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((address, port))
            socks.append(s)
    try:
        while True:
            ready, _, _ = select.select(socks, [], [], 1.0)
            for s in ready:
                packet, client = s.recvfrom(256)
                if packet == PROBE:
                    s.sendto(REPLY, client)
    finally:
        for s in socks:
            s.close()


def probe(ip_version, port):
    address = V4 if ip_version == 4 else V6
    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(0.7)
    try:
        s.sendto(PROBE, (address, port))
        data, _ = s.recvfrom(256)
        if data != REPLY:
            return 5
        return 0
    except socket.timeout:
        return 4
    except OSError:
        return 5
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("server", "probe"))
    parser.add_argument("--family", type=int, choices=(4, 6))
    parser.add_argument("--port", type=int, choices=PORTS)
    args = parser.parse_args()
    if args.mode == "server":
        if args.family is not None or args.port is not None:
            raise SystemExit(2)
        server()
    else:
        if args.family is None or args.port is None:
            raise SystemExit(2)
        raise SystemExit(probe(args.family, args.port))


if __name__ == "__main__":
    main()
