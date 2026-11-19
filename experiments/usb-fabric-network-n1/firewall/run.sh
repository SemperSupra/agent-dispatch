#!/bin/sh
set -eu
# Executed ONLY inside a disposable Docker network namespace with NET_ADMIN.
# Never run this on a host or a live managed network.
test "${USB_NET_DISPOSABLE:-}" = "YES" || { echo N2_NFT_NAMESPACE_UNVERIFIED=RED; exit 41; }
test "$(cat /proc/1/comm)" = "sh" || { echo N2_NFT_UNEXPECTED_PID1=RED; exit 42; }
ip -o link show | grep -q 'lo:'
if ip -o link show | grep -v 'lo:' | grep -q .; then echo N2_NFT_EXTRA_IFACE=RED; exit 43; fi
ip link set lo up
nft -f /dev/stdin <<'NFT'
table inet usbnet_n2_test {
 chain input {
  type filter hook input priority 0; policy accept;
  tcp dport 3240 ip saddr 127.0.0.1 accept
  tcp dport 3240 drop
 }
}
NFT
# Closing/withdrawing an allow rule must block newly created flows; never
# claim this test proves existing-flow USB-level detach or lease revocation.
python3 /opt/n2/check.py
nft delete table inet usbnet_n2_test
if nft list tables | grep -q usbnet_n2_test; then echo N2_NFT_CLEANUP=RED; exit 45; fi
echo N2_NFT_CLEANUP=PASS
echo N2_NFT_USB_BROKER_AND_LIVE_REVOCATION=NOT_TESTED
