#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

DUTS = {
    "dut-a": {"ip":"192.168.77.11","peer":"192.168.77.12","rdte_role":"Multi-AP-Controller-and-Agent"},
    "dut-b": {"ip":"192.168.77.12","peer":"192.168.77.11","rdte_role":"Multi-AP-Agent"},
}

def write(p: Path, s: str, mode=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s)
    if mode is not None: p.chmod(mode)

def identity_script(dut, gen, ip):
    return f"""#!/bin/sh
uci set system.@system[0].hostname='{dut}-{gen}'
uci set network.lan.ipaddr='{ip}'
uci set network.lan.netmask='255.255.255.0'
uci commit system
uci commit network
exit 0
"""

def rc_gold(dut, peer):
    return f"""#!/bin/sh
(
  sleep 10
  echo 'RDTE_BOOT_MARKER {dut} gold' > /dev/ttyS0
  ubus call system board > /dev/ttyS0 2>&1 || true
  ip -4 addr show br-lan > /dev/ttyS0 2>&1 || true
  ping -c 1 -W 1 {peer} >/dev/null 2>&1 && echo 'RDTE_PEER_PING=1' > /dev/ttyS0 || echo 'RDTE_PEER_PING=0' > /dev/ttyS0
  echo 'RDTE_GOLD_READY=1' > /dev/ttyS0
) &
exit 0
"""

def rc_rdte(dut, peer, role):
    controller = "1" if "Controller" in role else "0"
    return f"""#!/bin/sh
(
  sleep 12
  echo 'RDTE_BOOT_MARKER {dut} rdte' > /dev/ttyS0
  if ! lsmod | grep -q '^mac80211_hwsim'; then modprobe mac80211_hwsim radios=2 >/tmp/rdte-modprobe.log 2>&1 || true; fi
  rm -f /etc/config/wireless
  wifi config >/tmp/rdte-wifi-config.log 2>&1 || true
  radio=$(uci show wireless 2>/dev/null | sed -n 's/^wireless\.\([^.=]*\)=wifi-device.*/\1/p' | head -1)
  iface=$(uci show wireless 2>/dev/null | sed -n 's/^wireless\.\([^.=]*\)=wifi-iface.*/\1/p' | head -1)
  if [ -n "$radio" ] && [ -n "$iface" ]; then
    uci set wireless.$radio.disabled='0'
    uci set wireless.$radio.channel='1'
    uci set wireless.$radio.band='2g'
    uci set wireless.$radio.htmode='HT20'
    for dev in $(uci show wireless 2>/dev/null | sed -n 's/^wireless\.\([^.=]*\)=wifi-device.*/\1/p'); do
      uci -q delete wireless.$dev.country >/dev/null 2>&1 || true
    done
    uci set wireless.$iface.device="$radio"
    uci set wireless.$iface.disabled='0'
    uci set wireless.$iface.mode='ap'
    uci set wireless.$iface.network='lan'
    uci set wireless.$iface.ssid='rdte-prehil'
    uci set wireless.$iface.encryption='none'
    uci commit wireless
    /etc/init.d/network restart >/tmp/rdte-network.log 2>&1 || true
  fi
  sleep 8
  actual=$(iw dev 2>/dev/null | awk '$1=="Interface"{{print $2}}' | head -1)
  [ -n "$actual" ] || actual='wlan0'
  uci set prplmesh.config.enabled='1'
  uci set prplmesh.config.management_mode='{role}'
  uci set prplmesh.config.mandatory_interfaces="$actual"
  uci set prplmesh.config.backhaul_wire_iface='br-lan'
  uci set prplmesh.main_24_5.ssid='rdte-prehil'
  uci set prplmesh.main_24_5.key='rdte-prehil-pass'
  uci set prplmesh.main_24_5.encryption='psk2'
  uci commit prplmesh
  /etc/init.d/prplmesh restart >/tmp/rdte-prplmesh.log 2>&1 || true
  sleep 15
  cat /tmp/rdte-prplmesh.log > /dev/ttyS0 2>&1 || true
  ps w > /dev/ttyS0 2>&1 || true
  iw dev > /dev/ttyS0 2>&1 || true
  ping -c 2 -W 1 {peer} >/dev/null 2>&1 && echo 'RDTE_PEER_PING=1' > /dev/ttyS0 || echo 'RDTE_PEER_PING=0' > /dev/ttyS0
  echo 'RDTE_EXPECT_CONTROLLER={controller}' > /dev/ttyS0
  echo 'RDTE_ROLE_READY=1' > /dev/ttyS0
) &
exit 0
"""

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("output"); a=ap.parse_args()
    root=Path(a.output)
    for dut, d in DUTS.items():
        for gen in ("gold","rdte"):
            r=root/dut/gen
            meta={
              "schema":"wrt-prehil-config-generation/v1",
              "dut":dut, "generation":gen,
              "emulation_ip":d["ip"], "peer_ip":d["peer"],
              "role":("gold-baseline" if gen=="gold" else d["rdte_role"]),
              "physical_write_authority":"DENIED_PREHIL",
              "note":"Emulator-qualified configuration semantics only; physical slot/network identities remain R1/R2 observations."
            }
            write(r/"etc/rdte/generation.json",json.dumps(meta,indent=2,sort_keys=True)+"\n")
            write(r/"etc/uci-defaults/90-rdte-identity",identity_script(dut,gen,d["ip"]),0o755)
            write(r/"etc/rc.local",rc_gold(dut,d["peer"]) if gen=="gold" else rc_rdte(dut,d["peer"],d["rdte_role"]),0o755)
    print(json.dumps({"schema":"wrt-prehil-config-render/v1","root":str(root),"generations":4},indent=2))

if __name__=="__main__": main()
