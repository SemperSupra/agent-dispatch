#!/bin/sh
# R1 read-only WRT inventory collector.
# Intentionally performs no fw_setenv, sysupgrade, mount, package, or MTD writes.
set -u

OUT="${1:-/tmp/rdte-r1-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"

run() {
  name="$1"; shift
  ("$@" > "$OUT/$name.txt" 2>&1) || true
}

{
  echo "schema=rdte-wrt-r1-readonly/v1"
  date -u +"captured_utc=%Y-%m-%dT%H:%M:%SZ"
  echo "persistent_writes_performed=false"
  echo "authority=R1_READ_ONLY"
} > "$OUT/meta.txt"

run uname uname -a
[ -f /etc/openwrt_release ] && cp /etc/openwrt_release "$OUT/openwrt_release.txt"
[ -f /tmp/sysinfo/board_name ] && cp /tmp/sysinfo/board_name "$OUT/board_name.txt"
[ -f /tmp/sysinfo/model ] && cp /tmp/sysinfo/model "$OUT/model.txt"
[ -f /proc/cmdline ] && cp /proc/cmdline "$OUT/cmdline.txt"
[ -f /proc/mtd ] && cp /proc/mtd "$OUT/proc-mtd.txt"
run mounts mount
run df df -h
run block block info
run ubus-board ubus call system board
run ubus-list ubus list
run network ubus call network.interface dump
run uci-network uci show network
run uci-wireless uci show wireless
run uci-prplmesh uci show prplmesh

if command -v fw_printenv >/dev/null 2>&1; then
  run fw-printenv fw_printenv
  for key in boot_part bootcount boot_count bootlimit altbootcmd; do
    val="$(fw_printenv -n "$key" 2>/dev/null || true)"
    [ -n "$val" ] && printf '%s=%s\n' "$key" "$val"
  done > "$OUT/boot-env-selected.txt"
else
  echo "fw_printenv unavailable" > "$OUT/fw-printenv.txt"
fi

if command -v ubinfo >/dev/null 2>&1; then run ubinfo ubinfo -a; fi
if command -v lsblk >/dev/null 2>&1; then run lsblk lsblk -a -o NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINTS; fi
if command -v blkid >/dev/null 2>&1; then run blkid blkid; fi

for p in /sys/class/mtd/mtd*; do
  [ -d "$p" ] || continue
  n="$(basename "$p")"
  {
    printf 'name='; cat "$p/name" 2>/dev/null || true
    printf 'size='; cat "$p/size" 2>/dev/null || true
    printf 'erasesize='; cat "$p/erasesize" 2>/dev/null || true
    printf 'writesize='; cat "$p/writesize" 2>/dev/null || true
  } > "$OUT/$n.txt"
done

run modules lsmod
run dmesg dmesg
run logread logread
if command -v iw >/dev/null 2>&1; then
  run iw-dev iw dev
  run iw-phy iw phy
  run iw-reg iw reg get
  for phy in /sys/class/ieee80211/*; do
    [ -e "$phy" ] || continue
    p="$(basename "$phy")"
    (iw phy "$p" info > "$OUT/iw-$p-info.txt" 2>&1) || true
  done
fi
run processes ps w

for f in /lib/firmware/mwlwifi/W8964.bin /lib/firmware/mwlwifi/88W8964.bin /lib/firmware/W8964.bin; do
  if [ -f "$f" ]; then
    sha256sum "$f" >> "$OUT/wifi-firmware-sha256.txt"
    wc -c "$f" >> "$OUT/wifi-firmware-size.txt"
  fi
done

for k in mwlwifi mac80211 cfg80211; do
  if [ -d "/sys/module/$k" ]; then
    {
      echo "module=$k"
      [ -f "/sys/module/$k/version" ] && cat "/sys/module/$k/version"
      [ -L "/sys/module/$k/drivers" ] && readlink -f "/sys/module/$k/drivers"
    } > "$OUT/module-$k.txt"
  fi
done

# The authoritative machine descriptor is reduced on the HIL host after retrieval.
# Keep the DUT collector POSIX/BusyBox-only; do not require Python or install packages.
echo "$OUT"
