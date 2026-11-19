#!/bin/sh
set -eu
# Executed only with NET_ADMIN inside disposable docker --network none.
test "${USB_NET_DISPOSABLE:-}" = YES || { echo N3_NOT_DISPOSABLE=RED; exit 41; }
test "$(cat /proc/1/comm)" = sh || { echo N3_BAD_PID1=RED; exit 42; }
if ip -o link show | grep -v 'lo:' | grep -q .; then echo N3_EXTRA_INTERFACE=RED;exit 43;fi
ip link set lo up
python3 /opt/n3/check.py
if nft list tables | grep -q usbnet_n3; then echo N3_LEAKED_TABLE=RED;exit 44;fi
echo N3_CLEANUP=PASS
