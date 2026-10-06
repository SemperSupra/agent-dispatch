#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?output directory required}"
ROOT_REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${RUNNER_TEMP:-/tmp}/wrt-r1-ssh-sim"
rm -rf "$WORK"; mkdir -p "$WORK" "$OUT" "$WORK/home/.ssh"

VER=25.12.5
IB_NAME="openwrt-imagebuilder-${VER}-x86-64.Linux-x86_64"
ARCHIVE="$WORK/$IB_NAME.tar.zst"
URL="https://downloads.openwrt.org/releases/${VER}/targets/x86/64/$IB_NAME.tar.zst"
IB_SHA="313221253d9bac534e4a4ee6492a4941b4ba0f43200eceb8d16a4785470ae9df"

curl -fL --retry 2 --connect-timeout 20 "$URL" -o "$ARCHIVE"
test "$(sha256sum "$ARCHIVE" | awk '{print $1}')" = "$IB_SHA"
tar --use-compress-program=unzstd -xf "$ARCHIVE" -C "$WORK"
IB="$WORK/$IB_NAME"

ssh-keygen -q -t ed25519 -N "" -f "$WORK/r1sim-key"
mkdir -p "$WORK/overlay/etc/dropbear" "$WORK/overlay/etc/uci-defaults"
cp "$WORK/r1sim-key.pub" "$WORK/overlay/etc/dropbear/authorized_keys"
chmod 600 "$WORK/overlay/etc/dropbear/authorized_keys"
cat > "$WORK/overlay/etc/uci-defaults/99-r1-sim-network" <<'EOF'
#!/bin/sh
uci set network.lan.proto='dhcp'
uci -q delete network.lan.ipaddr
uci -q delete network.lan.netmask
uci set network.lan.device='eth0'
uci commit network
exit 0
EOF
chmod +x "$WORK/overlay/etc/uci-defaults/99-r1-sim-network"

(
  cd "$IB"
  make image PROFILE=generic PACKAGES="dropbear ip-full" FILES="$WORK/overlay" ROOTFS_PARTSIZE=160 > "$OUT/imagebuilder.log" 2>&1
)
gz="$(find "$IB/bin/targets/x86/64" -type f -name '*generic-ext4-combined.img.gz' -print -quit)"
test -n "$gz"
gzip -dc "$gz" > "$WORK/r1sim.img"
sha256sum "$gz" > "$OUT/synthetic-image-sha256.txt"

cat > "$WORK/home/.ssh/config" <<EOF
Host r1sim
  HostName 127.0.0.1
  Port 2222
  User root
  IdentityFile $WORK/r1sim-key
  IdentitiesOnly yes
  BatchMode yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
EOF
chmod 600 "$WORK/home/.ssh/config"

set +e
qemu-system-x86_64 -machine pc -m 512 -nographic \
  -drive file="$WORK/r1sim.img",format=raw,if=virtio \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:71:01:01 \
  > "$OUT/qemu-serial.log" 2>&1 &
QPID=$!
set -e
trap 'kill "$QPID" >/dev/null 2>&1 || true; wait "$QPID" >/dev/null 2>&1 || true' EXIT

export HOME="$WORK/home"
ready=0
for i in $(seq 1 60); do
  if ssh r1sim "printf R1_SIM_SSH_OK" > "$OUT/ssh-probe.txt" 2> "$OUT/ssh-probe.err"; then
    ready=1; break
  fi
  sleep 2
done
test "$ready" -eq 1

R1OUT="$OUT/r1-evidence"
set +e
bash "$ROOT_REPO/tools/wrt_hil_prep/payload/scripts/r1-readonly-remote.sh" r1sim "$R1OUT" > "$OUT/wrapper-output.txt" 2> "$OUT/wrapper-error.txt"
wrc=$?
set -e
printf '%s\n' "$wrc" > "$OUT/wrapper.rc"
test "$wrc" -eq 0

export OUT R1OUT
python3 - <<'PY' > "$OUT/verdict.json"
import json,os,pathlib
o=pathlib.Path(os.environ["OUT"]); r=pathlib.Path(os.environ["R1OUT"])
d=json.load(open(r/"device-descriptor.json"))
meta=(r/"meta.txt").read_text(errors="replace")
v={
 "schema":"wrt-r1-remote-wrapper-openwrt-synthetic/v1",
 "ssh_reachable":(o/"ssh-probe.txt").read_text(errors="replace")=="R1_SIM_SSH_OK",
 "wrapper_rc":int((o/"wrapper.rc").read_text().strip()),
 "meta_read_only_marker":"persistent_writes_performed=false" in meta,
 "descriptor_authority":d.get("write_authority"),
 "r1_inventory_minimum_complete":bool(d.get("r1_inventory_minimum_complete")),
 "ready_for_r2":bool(d.get("ready_for_r2")),
 "r2_admission_state":d.get("r2_admission",{}).get("state"),
 "synthetic_guest_not_physical_wrt":True,
 "claim":"remote_wrapper_transport_collection_reduction_only",
 "physical_write_authority":"DENIED_PREHIL"
}
v["passed"]=(v["ssh_reachable"] and v["wrapper_rc"]==0 and v["meta_read_only_marker"] and
             v["descriptor_authority"]=="DENIED_R1_READ_ONLY" and not v["ready_for_r2"] and
             v["r2_admission_state"]=="BLOCKED_REQUIRES_EXTERNAL_PRECONDITIONS")
print(json.dumps(v,indent=2,sort_keys=True))
PY
cat "$OUT/verdict.json"
python3 -c 'import json,sys; raise SystemExit(0 if json.load(open(sys.argv[1]))["passed"] else 1)' "$OUT/verdict.json"
