#!/usr/bin/env python3
"""Read-only public-hosted Linux capability and NetVSC-offload census.

No IP, MAC, interface name, hostname, credentials or private traffic emitted.
Only counts and supported/active NIC offload flags are exposed.
"""
import json
import pathlib
import platform
import shutil
import subprocess

INTERESTING_FEATURES = frozenset({
    "rx-checksumming", "tx-checksumming",
    "generic-receive-offload", "generic-segmentation-offload",
    "tcp-segmentation-offload", "rx-udp-gro-forwarding",
})


def module_available(name):
    return pathlib.Path("/sys/module", name).exists()


def module_listed(name):
    try:
        with open("/proc/modules", encoding="utf-8") as stream:
            return any(line.startswith(name + " ") for line in stream)
    except OSError:
        return False


def parse_current_channels(output):
    """Read ethtool -l *current* counts, not pre-set maxima."""
    if "Current hardware settings:" not in output:
        return None
    result = {}
    section = output.split("Current hardware settings:", 1)[1]
    for line in section.splitlines():
        if ":" not in line:
            continue
        key, value = line.strip().split(":", 1)
        if key in ("RX", "TX", "Combined") and value.strip().isdigit():
            parsed = int(value.strip())
            if 0 <= parsed <= 4096:
                result[key.lower()] = parsed
    return result if result else None


def netvsc_summary():
    counts = {"active_netvsc_interfaces": 0, "offload_readback_success": 0,
              "channel_readback_success": 0, "current_combined_channels_total": 0,
              "feature_enabled_counts": {name: 0 for name in sorted(INTERESTING_FEATURES)}}
    if platform.system() != "Linux" or not shutil.which("ethtool"):
        return counts
    for iface in sorted(pathlib.Path("/sys/class/net").iterdir()):
        # Device symlink identifies driver, not a guess based on an interface name.
        driver_link = iface / "device" / "driver"
        try:
            driver = driver_link.resolve(strict=True).name
        except (OSError, RuntimeError):
            continue
        if driver != "hv_netvsc":
            continue
        counts["active_netvsc_interfaces"] += 1
        try:
            channels = subprocess.run(["ethtool", "-l", iface.name], check=True,
                                      capture_output=True, text=True, timeout=4)
            current = parse_current_channels(channels.stdout)
            if current is not None:
                counts["channel_readback_success"] += 1
                counts["current_combined_channels_total"] += current.get("combined", 0)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        try:
            out = subprocess.run(["ethtool", "-k", iface.name], check=True,
                                 capture_output=True, text=True, timeout=4)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
        counts["offload_readback_success"] += 1
        for line in out.stdout.splitlines():
            if ":" not in line:
                continue
            key, value = line.strip().split(":", 1)
            if key in INTERESTING_FEATURES and value.strip().startswith("on"):
                counts["feature_enabled_counts"][key] += 1
    return counts


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
        "netvsc": netvsc_summary() if linux else {},
        "privileged_kernel_network_tests": "NOT_RUN",
        "tunnel_and_packet_evidence": "NOT_RUN",
        "physical_nic_benchmark": "NOT_RUN",
    }
    if linux:
        marker = pathlib.Path("/sys/hypervisor/type")
        try:
            observations["hypervisor_type"] = marker.read_text().strip().lower()
        except OSError:
            observations["hypervisor_type"] = "UNAVAILABLE"
    return observations


if __name__ == "__main__":
    print(json.dumps(collect(), indent=2, sort_keys=True))
