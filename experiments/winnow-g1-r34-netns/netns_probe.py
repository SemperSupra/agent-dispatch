#!/usr/bin/env python3
"""R34 public runner OS network-namespace denial canary (synthetic only).

This is NOT a downloader, not a production sandbox, and not an Instagram
request. It must run with no CAP_NET_ADMIN or other effective capabilities,
in a disposable network namespace different from the host namespace.
"""
import errno
import json
import os
import pathlib
import socket
import sys

TEST_V4 = "192.0.2.1"  # RFC 5737 TEST-NET-1, never a real Instagram host.
TEST_V6 = "2001:db8::1"  # RFC 3849 documentation-only IPv6 prefix.
DENIED = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.EACCES,
    errno.EPERM,
    errno.EADDRNOTAVAIL,
    errno.EAFNOSUPPORT,
    errno.EPROTONOSUPPORT,
    errno.ENETDOWN,
}


def no_ipv4_default():
    lines = pathlib.Path("/proc/net/route").read_text().splitlines()
    return all(
        len(fields) < 8 or fields[1] != "00000000" or fields[7] != "00000000"
        for fields in (line.split() for line in lines[1:])
    )


def no_ipv6_default():
    route = pathlib.Path("/proc/net/ipv6_route")
    if not route.exists():
        return True
    lines = route.read_text().splitlines()
    return all(
        len(fields) < 2 or fields[0] != "0" * 32 or fields[1] != "00000000"
        for fields in (line.split() for line in lines)
    )


def denied_connect(family, address):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as stream:
            stream.settimeout(0.75)
            result = stream.connect_ex((address, 443))
    except OSError as exc:
        result = exc.errno or 0
    if result not in DENIED:
        raise RuntimeError("R34_OUTBOUND_DENIAL_CANARY_FAILED: errno=%d" % result)
    return {"address_class": "documentation-only", "errno": result, "denied": True}


def main():
    if len(sys.argv) != 2 or not sys.argv[1].startswith("net:["):
        raise RuntimeError("R34_HOST_NAMESPACE_REFERENCE_REQUIRED")
    host_namespace = sys.argv[1]
    child_namespace = os.readlink("/proc/self/ns/net")
    if child_namespace == host_namespace:
        raise RuntimeError("R34_NETWORK_NAMESPACE_NOT_ISOLATED")
    if os.geteuid() != 65534 or os.getegid() != 65534:
        raise RuntimeError("R34_NOT_UNPRIVILEGED")
    status = pathlib.Path("/proc/self/status").read_text().splitlines()
    cap_eff = next((line.split()[1] for line in status if line.startswith("CapEff:")), None)
    if cap_eff is None or int(cap_eff, 16) != 0:
        raise RuntimeError("R34_CAPABILITIES_STILL_EFFECTIVE")
    if not no_ipv4_default() or not no_ipv6_default():
        raise RuntimeError("R34_DEFAULT_ROUTE_PRESENT")
    probes = [
        denied_connect(socket.AF_INET, TEST_V4),
        denied_connect(socket.AF_INET6, TEST_V6),
    ]
    report = {
        "schema_version": 1,
        "scope": "EPHEMERAL_GHA_OS_NETWORK_NAMESPACE_CAPABILITY_PROBE_ONLY",
        "namespace_differs_from_host": True,
        "nonroot_uid_gid": True,
        "zero_effective_capabilities": True,
        "ipv4_default_route_absent": True,
        "ipv6_default_route_absent": True,
        "synthetic_connection_probes": probes,
        "live_instagram_requests": 0,
        "private_winnow_source_present": False,
        "gallery_dl_confined": False,
        "parth_dl_confined": False,
        "production_runtime_admitted": False,
        "source_rights_granted": False,
    }
    print(json.dumps(report, sort_keys=True))
    print("R34_EPHEMERAL_NETWORK_NAMESPACE_DENIAL_PASS probes=2 nonroot=PASS routes=NONE source=NOT_RUN")


if __name__ == "__main__":
    main()
