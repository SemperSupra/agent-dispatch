#!/usr/bin/env bash
set -euo pipefail
E2_DIR="${1:?e2 artifact directory required}"
OUT="${2:?output directory required}"
ROOT_REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${RUNNER_TEMP:-/tmp}/wrt-rdte-fresh-parity"
rm -rf "$WORK"; mkdir -p "$WORK" "$OUT"

VER=25.12.5
IB_NAME="openwrt-imagebuilder-${VER}-x86-64.Linux-x86_64"
ARCHIVE="$WORK/$IB_NAME.tar.zst"
URL="https://downloads.openwrt.org/releases/${VER}/targets/x86/64/$IB_NAME.tar.zst"
IB_SHA="313221253d9bac534e4a4ee6492a4941b4ba0f43200eceb8d16a4785470ae9df"
PKG_SHA="ce91228d204b68cf37d0c46bf5f7492cfe3ac9d83463cb5d47cafb84197336d7"
PKGS="prplmesh kmod-mac80211-hwsim iw-full wpad-openssl ip-full -wpad-basic-mbedtls"

curl -fL --retry 2 --connect-timeout 20 "$URL" -o "$ARCHIVE"
test "$(sha256sum "$ARCHIVE" | awk '{print $1}')" = "$IB_SHA"

pkg="$(find "$E2_DIR" -type f -name 'prplmesh-6.0.1-r1.apk' -print -quit)"
test -n "$pkg"
test "$(sha256sum "$pkg" | awk '{print $1}')" = "$PKG_SHA"

python3 "$ROOT_REPO/tools/wrt_hil_prequal/generate_dut_overlays.py" "$WORK/overlays" > "$OUT/config-render.json"
find "$WORK/overlays" -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/config-sha256.txt"

build_fresh() {
  local dut="$1"
  local sub="$WORK/ib-$dut"
  mkdir -p "$sub"
  tar --use-compress-program=unzstd -xf "$ARCHIVE" -C "$sub"
  local ib="$sub/$IB_NAME"
  mkdir -p "$ib/packages"
  cp "$pkg" "$ib/packages/"
  (
    cd "$ib"
    make image PROFILE=generic PACKAGES="$PKGS" FILES="$WORK/overlays/$dut/rdte" ROOTFS_PARTSIZE=192 > "$OUT/build-$dut.log" 2>&1
  )
  local gz
  gz="$(find "$ib/bin/targets/x86/64" -type f -name '*generic-ext4-combined.img.gz' -print -quit)"
  test -n "$gz"
  cp "$gz" "$WORK/$dut.img.gz"
  gzip -dc "$gz" > "$WORK/$dut.img"
  sha256sum "$gz" > "$OUT/$dut-image-sha256.txt"
}

build_fresh dut-a
build_fresh dut-b

boot_standalone() {
  local dut="$1" mac="$2"
  set +e
  timeout 105 qemu-system-x86_64 -machine pc -m 768 -nographic     -drive file="$WORK/$dut.img",format=raw,if=virtio     -netdev user,id=n0 -device virtio-net-pci,netdev=n0,mac="$mac"     > "$OUT/$dut-standalone.log" 2>&1
  echo $? > "$OUT/$dut-standalone.rc"
  set -e
}

boot_standalone dut-a 52:54:00:77:00:0a
boot_standalone dut-b 52:54:00:77:00:0b

export OUT
python3 - <<'PY' > "$OUT/standalone-verdict.json"
import json,os,pathlib
o=pathlib.Path(os.environ["OUT"])
def t(n): return (o/n).read_text(errors="replace") if (o/n).exists() else ""
def one(dut, expect_controller):
    s=t(f"{dut}-standalone.log")
    return {
      "radio": any(line.lstrip().startswith("Interface wlan") for line in s.splitlines()),
      "hostapd_process": "/usr/sbin/hostapd" in s,
      "transport": "ieee1905_transport" in s,
      "agent": "beerocks_agent" in s,
      "controller": "beerocks_controller" in s,
      "role_marker": f"RDTE_BOOT_MARKER {dut} rdte" in s and "RDTE_ROLE_READY=1" in s,
      "controller_semantics": (("beerocks_controller" in s) == expect_controller)
    }
v={"schema":"wrt-rdte-fresh-standalone-parity/v1",
   "dut_a":one("dut-a",True),
   "dut_b":one("dut-b",False)}
required=("radio","hostapd_process","transport","agent","role_marker","controller_semantics")
v["passed"]=all(all(x.get(k,False) for k in required) for x in (v["dut_a"],v["dut_b"]))
print(json.dumps(v,indent=2,sort_keys=True))
PY

standalone_pass="$(python3 -c 'import json,sys; print("1" if json.load(open(sys.argv[1]))["passed"] else "0")' "$OUT/standalone-verdict.json")"
if [ "$standalone_pass" = 1 ]; then
  set +e
  timeout 135 qemu-system-x86_64 -machine pc -m 768 -nographic     -drive file="$WORK/dut-a.img",format=raw,if=virtio     -netdev socket,id=n0,listen=127.0.0.1:31338 -device virtio-net-pci,netdev=n0,mac=52:54:00:77:00:0a     > "$OUT/dut-a-dual.log" 2>&1 &
  PA=$!
  sleep 2
  timeout 135 qemu-system-x86_64 -machine pc -m 768 -nographic     -drive file="$WORK/dut-b.img",format=raw,if=virtio     -netdev socket,id=n0,connect=127.0.0.1:31338 -device virtio-net-pci,netdev=n0,mac=52:54:00:77:00:0b     > "$OUT/dut-b-dual.log" 2>&1 &
  PB=$!
  wait "$PA"; echo $? > "$OUT/dut-a-dual.rc"
  wait "$PB"; echo $? > "$OUT/dut-b-dual.rc"
  set -e
else
  : > "$OUT/dut-a-dual.log"
  : > "$OUT/dut-b-dual.log"
fi

python3 - <<'PY' > "$OUT/verdict.json"
import json,os,pathlib
o=pathlib.Path(os.environ["OUT"])
s=json.load(open(o/"standalone-verdict.json"))
def t(n): return (o/n).read_text(errors="replace") if (o/n).exists() else ""
a=t("dut-a-dual.log"); b=t("dut-b-dual.log")
dual={
 "attempted": bool(a or b),
 "a_agent": "beerocks_agent" in a,
 "b_agent": "beerocks_agent" in b,
 "a_controller": "beerocks_controller" in a,
 "b_controller_absent": "beerocks_controller" not in b,
 "a_peer_ping": "RDTE_PEER_PING=1" in a,
 "b_peer_ping": "RDTE_PEER_PING=1" in b,
 "a_radio": any(line.lstrip().startswith("Interface wlan") for line in a.splitlines()),
 "b_radio": any(line.lstrip().startswith("Interface wlan") for line in b.splitlines())
}
dual["passed"]=dual["attempted"] and all(v for k,v in dual.items() if k not in ("attempted","passed"))
v={
 "schema":"wrt-rdte-fresh-imagebuilder-parity/v1",
 "imagebuilder_sha256":"313221253d9bac534e4a4ee6492a4941b4ba0f43200eceb8d16a4785470ae9df",
 "prplmesh_sha256":"ce91228d204b68cf37d0c46bf5f7492cfe3ac9d83463cb5d47cafb84197336d7",
 "fresh_imagebuilder_per_dut":True,
 "standalone":s,
 "dual":dual,
 "physical_write_authority":"DENIED_PREHIL",
 "claim":"x86 configuration/service parity only"
}
v["passed"]=bool(s["passed"] and dual["passed"])
print(json.dumps(v,indent=2,sort_keys=True))
PY
cat "$OUT/verdict.json"
