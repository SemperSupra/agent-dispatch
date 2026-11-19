#!/usr/bin/env python3
"""Generate a disposable overlay around the exact R08 two-kernel USB/IP source.

This composes upstream nftables (binary and distro kernel modules) with the
existing test harness without editing its tracked sources.
"""
from pathlib import Path
import shutil, sys, subprocess
root=Path(__file__).resolve().parents[3]
stage=Path(sys.argv[1]).resolve()
sha="78235a5522ac18abe9a821f4bff1aee5ae42c4f0"
subprocess.run(["git","merge-base","--is-ancestor",sha,"HEAD"],cwd=root,check=True)
paths=[
 "experiments/pi-usb-fabric-r08/two-guest/Dockerfile",
 "experiments/pi-usb-fabric-r08/two-guest/provider.init",
 "experiments/pi-usb-fabric-r08/two-guest/consumer.init",
 "experiments/pi-usb-fabric-r08/two-guest/run.sh",
 "experiments/pi-usb-fabric-r06/transport/hid_evdev_observer.c",
]
for f in paths:
    target=stage/f
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(root/f,target)

def replace_one(path, old,new):
    txt=path.read_text()
    if txt.count(old)!=1: raise SystemExit("N3_G3B_SOURCE_DRIFT_RED: "+old)
    path.write_text(txt.replace(old,new))
d=stage/paths[0]
replace_one(d,"linux-image-amd64 initramfs-tools kmod usbip gcc libc6-dev", "linux-image-amd64 initramfs-tools kmod usbip nftables gcc libc6-dev")
replace_one(d,"for name in usbip usbipd; do", "for name in usbip usbipd nft; do")
replace_one(d,"usb_f_hid usbhid hid_generic evdev e1000; do", "usb_f_hid usbhid hid_generic evdev e1000 nf_tables; do")
provider=stage/paths[1]
needle="echo R08_PROVIDER_DISTINCT_KERNEL_BOOT=PASS >/dev/console"
firewall=r'''# Actual kernel nftables input enforcement, inside disposable guest ONLY.
if modprobe nf_tables >/dev/console 2>&1 && /usr/sbin/nft -f /dev/stdin <<'NFT'
table inet n3_usbip {
 chain input {
  type filter hook input priority 0; policy accept;
  tcp dport 3240 ip saddr 10.77.0.2 accept
  tcp dport 3240 drop
 }
}
NFT
then
 echo N3_PROVIDER_NFT_DENY_POLICY=PASS >/dev/console
else
 echo N3_PROVIDER_NFT_DENY_POLICY=RED >/dev/console
 sync
 poweroff -f
fi
'''
replace_one(provider,needle,needle+"\n"+firewall)
consumer=stage/paths[2]
needle="echo R08_CONSUMER_REMOTE_PROVIDER_DISCOVERED=PASS >/dev/console"
bad=r'''# Provider already answered an authorized discovery before this negative test.
# Now change source address within the same guest/network and require deny.
if /bin/busybox ip addr del 10.77.0.2/24 dev eth0 &&
   /bin/busybox ip addr add 10.77.0.3/24 dev eth0; then
 if /bin/busybox timeout 4 /usr/sbin/usbip list --remote 10.77.0.1 >/tmp/n3-denied.txt 2>&1; then
  echo N3_CONSUMER_UNAUTHORIZED_SOURCE_DENIED=RED >/dev/console
 else
  echo N3_CONSUMER_UNAUTHORIZED_SOURCE_DENIED=PASS >/dev/console
 fi
else
 echo N3_CONSUMER_UNAUTHORIZED_SOURCE_DENIED=RED >/dev/console
fi
/bin/busybox ip addr del 10.77.0.3/24 dev eth0 >/dev/console 2>&1 || :
if /bin/busybox ip addr add 10.77.0.2/24 dev eth0 >/dev/console 2>&1; then
 echo N3_CONSUMER_NETWORK_RESTORED=PASS >/dev/console
else
 echo N3_CONSUMER_NETWORK_RESTORED=RED >/dev/console
fi
'''
replace_one(consumer,needle,needle+"\n"+bad)
print("N3_G3B_PINNED_SOURCE_OVERLAY=PASS")
