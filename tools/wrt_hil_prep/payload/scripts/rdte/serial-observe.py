#!/usr/bin/env python3
"""Reduce a WRT serial-console transcript to conservative boot-state observations."""
import argparse, json, re
from pathlib import Path

PATTERNS = {
    "uboot_version": re.compile(r"\bU-Boot\s+([^\r\n]+)", re.I),
    "uboot_prompt": re.compile(r"(?:^|\n)\s*(?:Marvell|WRT|Venom|=>)\s*(?:>>|=>)?\s*$", re.I|re.M),
    "hit_key": re.compile(r"Hit any key to stop autoboot", re.I),
    "kernel_start": re.compile(r"(?:Starting kernel|Booting Linux|Linux version\s+\d)", re.I),
    "openwrt": re.compile(r"\bOpenWrt\b", re.I),
    "login": re.compile(r"\b(?:login:|root@[^:]+:)", re.I),
    "panic": re.compile(r"Kernel panic|not syncing:", re.I),
    "watchdog": re.compile(r"\bwatchdog\b", re.I),
    "reset": re.compile(r"\b(?:resetting|reset cause|reboot:|rebooting)\b", re.I),
}
BOOT_PART_RX = re.compile(r"\bboot_part\s*[=:]\s*([12])\b", re.I)

def parse(text):
    u = PATTERNS["uboot_version"].search(text)
    boot_parts = sorted(set(BOOT_PART_RX.findall(text)))
    return {
        "schema":"rdte-wrt-serial-observation/v1",
        "uboot_seen": bool(u or PATTERNS["hit_key"].search(text)),
        "uboot_version": u.group(1).strip() if u else None,
        "autoboot_interrupt_window_seen": bool(PATTERNS["hit_key"].search(text)),
        "uboot_prompt_seen": bool(PATTERNS["uboot_prompt"].search(text)),
        "kernel_start_seen": bool(PATTERNS["kernel_start"].search(text)),
        "openwrt_seen": bool(PATTERNS["openwrt"].search(text)),
        "login_or_shell_seen": bool(PATTERNS["login"].search(text)),
        "kernel_panic_seen": bool(PATTERNS["panic"].search(text)),
        "watchdog_text_seen": bool(PATTERNS["watchdog"].search(text)),
        "reset_text_seen": bool(PATTERNS["reset"].search(text)),
        "boot_part_observations": boot_parts,
        "boot_part_unambiguous": boot_parts[0] if len(boot_parts)==1 else None,
        "authority":"SENSOR_ONLY_NO_ACTUATION",
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("-o","--output")
    a=ap.parse_args()
    out=json.dumps(parse(Path(a.transcript).read_text(errors="replace")),indent=2,sort_keys=True)+"\n"
    if a.output: Path(a.output).write_text(out)
    else: print(out,end="")

if __name__=="__main__": main()
