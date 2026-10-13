#!/usr/bin/env python3
"""Strictly read-only generic Linux capability census (no network or account I/O).

A hosted Ubuntu runner is not a Hyper-V Linux guest just because its kernel
supports a module. Results are environment facts, not product qualification.
"""
import json
import os
import pathlib
import platform
import shutil


def module_available(name):
    """Presence of a loaded/built-in module, NOT hardware capability."""
    return pathlib.Path("/sys/module", name).exists()


def module_listed(name):
    try:
        with open("/proc/modules", encoding="utf-8") as f:
            return any(line.startswith(name + " ") for line in f)
    except OSError:
        return False


def collect():
    linux = platform.system() == "Linux"
    names = ("hv_netvsc", "hv_vmbus", "hv_utils", "hv_balloon",
             "hv_sock", "wireguard", "nf_tables", "nf_conntrack")
    observations = {
        "observation_class": "PUBLIC_HOSTED_READONLY",
        "os_family": platform.system(),
        "linux_kernel_release": platform.release() if linux else "not-linux",
        "hyperv_guest_verified": False,
        "modules_present_or_builtin": {name: (module_available(name) or module_listed(name))
                                       if linux else False for name in names},
        "tools": {name: bool(shutil.which(name)) for name in ("ip", "nft", "wg", "ethtool")},
        "privileged_kernel_network_tests": "NOT_RUN",
        "tunnel_and_packet_evidence": "NOT_RUN",
        "physical_nic_benchmark": "NOT_RUN",
    }
    if linux:
        # Hypervisor identification alone doesn't prove guest-driver operation.
        marker = pathlib.Path("/sys/hypervisor/type")
        try:
            observations["hypervisor_type"] = marker.read_text().strip().lower()
        except OSError:
            observations["hypervisor_type"] = "UNAVAILABLE"
    return observations


if __name__ == "__main__":
    print(json.dumps(collect(), indent=2, sort_keys=True))
