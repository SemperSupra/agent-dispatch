#!/usr/bin/env bash
# Read-only host USB HID, gadget, and biometric software capability census.
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel)"
old="$(git status --porcelain --untracked-files=all)"
[[ -z "$old" ]] || { echo PASSKEY_R1_SOURCE_DIRTY=RED;exit 10; }
echo PASSKEY_R1_RUNNER_OS="$(uname -srmo)"
echo PASSKEY_R1_CPU="$(nproc)"
echo PASSKEY_R1_KERNEL_CONFIG_AVAILABLE="$(test -r /boot/config-"$(uname -r)" && echo yes || echo no)"
for d in /dev/uhid /dev/hidraw0 /dev/kvm /dev/video0 /dev/snd;do
 if [[ -e "$d" ]];then
  echo "PASSKEY_R1_DEV_${d#/dev/}=$(stat -c '%F:%a:%U:%G' "$d")"
  [[ -r "$d" && -w "$d" ]] && echo "PASSKEY_R1_DEV_${d#/dev/}_USER_RW=yes" || echo "PASSKEY_R1_DEV_${d#/dev/}_USER_RW=no"
 else echo "PASSKEY_R1_DEV_${d#/dev/}=ABSENT";fi
done
for cmd in usbip usbipd modinfo lsusb fido2-token pcsc_scan v4l2-ctl arecord ffmpeg qemu-system-x86_64 adb emulator;do
 if command -v "$cmd" >/dev/null 2>&1;then
  echo "PASSKEY_R1_TOOL_${cmd}=PRESENT path=$(command -v "$cmd")"
 else echo "PASSKEY_R1_TOOL_${cmd}=ABSENT";fi
done
for m in uhid vhci-hcd vhci_hcd dummy_hcd usb_f_uvc libcomposite g_audio usb_f_uac2;do
 if command -v modinfo >/dev/null 2>&1 && modinfo "$m" >/dev/null 2>&1;then
  echo "PASSKEY_R1_KERNEL_MODULE_$m=DISCOVERED_NOT_LOADED"
 else
  echo "PASSKEY_R1_KERNEL_MODULE_$m=NOT_DISCOVERED"
 fi
done
if [[ -r /proc/config.gz ]];then
 zcat /proc/config.gz | grep -E '^CONFIG_(UHID|USBIP_VHCI_HCD|USB_DUMMY_HCD|USB_CONFIGFS_F_UVC|USB_CONFIGFS_F_UAC2|USB_LIBCOMPOSITE)=' | sed 's/^/PASSKEY_R1_KERNEL_CONFIG_/' || true
elif [[ -r /boot/config-$(uname -r) ]];then
 grep -E '^CONFIG_(UHID|USBIP_VHCI_HCD|USB_DUMMY_HCD|USB_CONFIGFS_F_UVC|USB_CONFIGFS_F_UAC2|USB_LIBCOMPOSITE)=' /boot/config-"$(uname -r)" | sed 's/^/PASSKEY_R1_KERNEL_CONFIG_/' || true
fi
test -d /sys/class/udc && find /sys/class/udc -mindepth 1 -maxdepth 1 -printf 'PASSKEY_R1_USB_UDC=%f\n' || true
test -d /sys/class/video4linux && find /sys/class/video4linux -mindepth 1 -maxdepth 1 -printf 'PASSKEY_R1_V4L2=%f\n' || true
echo PASSKEY_R1_NO_SUDO_MODPROBE_USB_ATTACH_OR_BIOMETRIC_INPUT=PASS
[[ "$(git status --porcelain --untracked-files=all)" == "$old" ]] || {echo PASSKEY_R1_SOURCE_TAINT=RED;exit 11;}
echo PASSKEY_R1_NON_MUTATING_VIRTUAL_PERIPHERAL_CENSUS=PASS
echo PASSKEY_R1_REAL_UHID_DEVICE_USBIP_CCID_UVC_UAC=NOT_TESTED
