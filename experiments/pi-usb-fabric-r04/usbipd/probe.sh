#!/usr/bin/env bash
set -Eeuo pipefail
echo "ARCH=$(uname -m)"
test "$(uname -m)" = aarch64
(dpkg -L linux-tools-common linux-tools-generic | grep -E 'usbip|linux-tools' || true) | tail -60
mapfile -t clients < <(find /usr/lib/linux-tools /usr/bin /usr/sbin -name usbip -print 2>/dev/null | sort -V)
mapfile -t servers < <(find /usr/lib/linux-tools /usr/bin /usr/sbin -name usbipd -print 2>/dev/null | sort -V)
if (( ${#clients[@]} == 0 || ${#servers[@]} == 0 )); then
 echo USBIP_NATIVE_USERSPACE_BINARIES=RED; exit 21
fi
client="${clients[-1]}"; server="${servers[-1]}"
printf 'USBFABRIC_USBIP_CLIENT=%s\nUSBFABRIC_USBIP_SERVER=%s\n' "$client" "$server"
"$client" version || :
"$server" --version || :
# True native USB/IP client attempts connection before server to prove fail-closed handling.
if timeout 5 "$client" list --remote 127.0.0.1 >/tmp/negative.txt 2>&1; then
 echo USBIP_ABSENT_SERVER_NEGATIVE=RED
 cat /tmp/negative.txt
 exit 22
fi
echo USBIP_ABSENT_SERVER_NEGATIVE=PASS
"$server" --debug --daemon >/tmp/server.log 2>&1 || {
 echo USBIPD_SERVER_START=RED; cat /tmp/server.log; exit 23;
}
# Actual localhost control request/response; no physical device exported.
for attempt in 1 2 3 4 5; do
 if timeout 4 "$client" list --remote 127.0.0.1 > /tmp/list.txt 2>&1; then
   echo USBIPD_NATIVE_CLIENT_SERVER_DISCOVERY=PASS
   cat /tmp/list.txt
   echo USBIPD_PHYSICAL_EXPORT=NOT_TESTED
   echo USBIPD_VHCI_ATTACH=NOT_TESTED
   echo USBIPD_URB_TRANSFER=NOT_TESTED
   exit 0
 fi
 sleep 1
done
echo USBIPD_NATIVE_CLIENT_SERVER_DISCOVERY=RED
cat /tmp/server.log /tmp/list.txt
exit 24
