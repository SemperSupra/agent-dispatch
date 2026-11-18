#!/bin/sh
# Runs ONLY inside disposable QEMU Linux guest.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /proc /sys /dev
if mount -t proc proc /proc; then echo USBFABRIC_R04_PROC_MOUNT=PASS >/dev/console; else echo USBFABRIC_R04_PROC_MOUNT=RED >/dev/console; fi
if mount -t sysfs sysfs /sys; then echo USBFABRIC_R04_SYSFS_MOUNT=PASS >/dev/console; else echo USBFABRIC_R04_SYSFS_MOUNT=RED >/dev/console; fi
mount -t devtmpfs devtmpfs /dev || :
echo USBFABRIC_R04_GUEST_BOOT=PASS >/dev/console
uname -r >/dev/console
for m in usbip_core usbip_host vhci_hcd usbip_vudc libcomposite dummy_hcd; do
 if modprobe "$m" >/dev/console 2>&1; then
   echo "USBFABRIC_R04_MODULE_${m}=LOADED" >/dev/console
 else
   echo "USBFABRIC_R04_MODULE_${m}=FAILED" >/dev/console
 fi
done
# Upstream USB/IP vUDC example explicitly requests num=1; otherwise no UDC may register.
modprobe -r usbip_vudc >/dev/console 2>&1 || :
if modprobe usbip_vudc num=1 >/dev/console 2>&1; then
 echo USBFABRIC_R04_VUDC_NUM1_LOAD=PASS >/dev/console
else
 echo USBFABRIC_R04_VUDC_NUM1_LOAD=RED >/dev/console
fi
mkdir -p /sys/kernel/config
if mount -t configfs configfs /sys/kernel/config >/dev/console 2>&1; then
 echo USBFABRIC_R04_CONFIGFS_MOUNT=PASS >/dev/console
else
 echo USBFABRIC_R04_CONFIGFS_MOUNT=RED >/dev/console
fi
if [ -d /sys/class/udc ]; then
 echo USBFABRIC_R04_UDC_ENUM_BEGIN >/dev/console
 ls -1 /sys/class/udc >/dev/console
 echo USBFABRIC_R04_UDC_ENUM_END >/dev/console
else
 echo USBFABRIC_R04_UDC_ENUM=ABSENT >/dev/console
fi
# First actual gadget binding gate: synthetic HID keyboard (no host keyboard or real USB).
g=/sys/kernel/config/usb_gadget/usbfabric_r05
if [ ! -d /sys/kernel/config/usb_gadget ] || [ ! -d /sys/class/udc/usbip-vudc.0 ]; then
  echo USBFABRIC_R05_GADGET_PREREQUISITE=RED >/dev/console
else
  mkdir -p "$g" "$g/strings/0x409" "$g/configs/c.1/strings/0x409"
  echo 0x1d6b > "$g/idVendor"
  echo 0x0104 > "$g/idProduct"
  echo 0x0100 > "$g/bcdDevice"
  echo 0x0200 > "$g/bcdUSB"
  echo R05SYNTHETIC > "$g/strings/0x409/serialnumber"
  echo USBFabric > "$g/strings/0x409/manufacturer"
  echo SyntheticHID > "$g/strings/0x409/product"
  echo HIDtest > "$g/configs/c.1/strings/0x409/configuration"
  echo 100 > "$g/configs/c.1/MaxPower"
  if modprobe usb_f_hid >/dev/console 2>&1; then echo USBFABRIC_R05_HID_FUNCTION_MODULE=PASS >/dev/console; else echo USBFABRIC_R05_HID_FUNCTION_MODULE=RED >/dev/console; fi
  mkdir -p "$g/functions/hid.usb0"
  echo 1 > "$g/functions/hid.usb0/protocol"
  echo 1 > "$g/functions/hid.usb0/subclass"
  echo 8 > "$g/functions/hid.usb0/report_length"
  printf '\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0' > "$g/functions/hid.usb0/report_desc"
  if [ "$(wc -c < "$g/functions/hid.usb0/report_desc")" = 63 ]; then
    echo USBFABRIC_R05_HID_DESCRIPTOR_63_BYTES=PASS >/dev/console
  else
    echo USBFABRIC_R05_HID_DESCRIPTOR_63_BYTES=RED >/dev/console
  fi
  ln -s "$g/functions/hid.usb0" "$g/configs/c.1/hid.usb0"
  if echo usbip-vudc.0 > "$g/UDC"; then
    if [ "$(cat "$g/UDC")" = usbip-vudc.0 ]; then
      echo USBFABRIC_R05_GADGET_UDC_BOUND=PASS >/dev/console
    else
      echo USBFABRIC_R05_GADGET_UDC_BOUND=RED >/dev/console
    fi
  else
    echo USBFABRIC_R05_GADGET_UDC_BOUND=RED >/dev/console
  fi
  if [ -c /dev/hidg0 ]; then
    echo USBFABRIC_R05_HIDG0_CHAR_DEVICE=PASS >/dev/console
  else
    echo USBFABRIC_R05_HIDG0_CHAR_DEVICE=RED >/dev/console
  fi
fi
# Actual USB/IP userland server-client path; all processes stay inside the QEMU guest.
mkdir -p /tmp /var/run
# usbip's vhci connection-record directory requires an existing /var/run parent.
for mod in usbhid hid_generic evdev; do modprobe "$mod" >/dev/console 2>&1 || :; done
if [ ! -x /usr/sbin/usbip ] || [ ! -x /usr/sbin/usbipd ]; then
  echo USBFABRIC_R06_USBIP_BINARIES=RED >/dev/console
else
  echo USBFABRIC_R06_USBIP_BINARIES=PASS >/dev/console
  /bin/busybox ip link set lo up >/dev/console 2>&1 || :
  if /usr/sbin/usbip list --remote 127.0.0.1 >/tmp/r06-no-daemon.txt 2>&1; then
    echo USBFABRIC_R06_NO_SERVER_NEGATIVE=RED >/dev/console
  else
    echo USBFABRIC_R06_NO_SERVER_NEGATIVE=PASS >/dev/console
  fi
  /usr/sbin/usbipd --device --debug >/dev/console 2>&1 &
  daemonpid="$!"
  sleep 2
  if /usr/sbin/usbip list --remote 127.0.0.1 >/tmp/r06-export.txt 2>&1; then
    cat /tmp/r06-export.txt >/dev/console
    if grep -q usbip-vudc.0 /tmp/r06-export.txt; then
      echo USBFABRIC_R06_REAL_USBIP_VUDC_EXPORT=PASS >/dev/console
      if /usr/sbin/usbip attach --remote 127.0.0.1 --busid usbip-vudc.0 >/tmp/r06-attach.txt 2>&1; then
        cat /tmp/r06-attach.txt >/dev/console
        # The virtual controller's kernel attach is asynchronous. Observe up to five real port polls.
        echo USBFABRIC_R06_CLIENT_IMPORT_REQUEST_ACCEPTED=PASS >/dev/console
        connected=no
        for probe in 1 2 3 4 5; do
          /usr/sbin/usbip port >/tmp/r06-port.txt 2>&1 || :
          if grep -q usbip-vudc.0 /tmp/r06-port.txt; then connected=yes; break; fi
          sleep 1
        done
        cat /tmp/r06-port.txt >/dev/console
        if [ "$connected" = yes ]; then
          echo USBFABRIC_R06_REAL_VHCI_IMPORT=PASS >/dev/console
          if [ -r /proc/bus/input/devices ]; then cat /proc/bus/input/devices >/dev/console; fi
          eventdev="$(/bin/busybox awk '/Name="USBFabric SyntheticHID"/{matched=1;next} matched && /Handlers=/ {for(i=1;i<=NF;i++) if($i ~ /^event[0-9]+$/){print $i;exit}}' /proc/bus/input/devices)"
          if [ -n "$eventdev" ] && [ -c "/dev/input/$eventdev" ]; then
            echo "USBFABRIC_R06_EVDEV_PATH=/dev/input/$eventdev" >/dev/console
            /usr/bin/hid_evdev_observer "/dev/input/$eventdev" >/tmp/r06-evdev.txt 2>&1 &
            observerpid="$!"
            sleep 1
            /bin/busybox printf '\x00\x00\x04\x00\x00\x00\x00\x00' >/dev/hidg0
            sleep 1
            /bin/busybox printf '\x00\x00\x00\x00\x00\x00\x00\x00' >/dev/hidg0
            if wait "$observerpid"; then
              cat /tmp/r06-evdev.txt >/dev/console
              echo USBFABRIC_R06_GUEST_HID_INPUT_DATA=PASS >/dev/console
            else
              cat /tmp/r06-evdev.txt >/dev/console
              echo USBFABRIC_R06_GUEST_HID_INPUT_DATA=RED >/dev/console
            fi
          else
            echo USBFABRIC_R06_GUEST_HID_INPUT_DATA=RED >/dev/console
          fi
        else
          echo USBFABRIC_R06_REAL_VHCI_IMPORT=RED >/dev/console
        fi
        /usr/sbin/usbip detach --port 0 >/dev/console 2>&1 || :
      else
        cat /tmp/r06-attach.txt >/dev/console
        echo USBFABRIC_R06_REAL_VHCI_IMPORT=RED >/dev/console
      fi
    else
      echo USBFABRIC_R06_REAL_USBIP_VUDC_EXPORT=RED >/dev/console
    fi
  else
    cat /tmp/r06-export.txt >/dev/console
    echo USBFABRIC_R06_REAL_USBIP_VUDC_EXPORT=RED >/dev/console
  fi
  kill "$daemonpid" >/dev/console 2>&1 || :
fi
echo USBFABRIC_R06_TRANSPORT_PROBE_END=YES >/dev/console
echo USBFABRIC_R06_EVDEV_CHECK_COMPLETED=YES >/dev/console
echo USBFABRIC_R05_GADGET_PROBE_END=YES >/dev/console
echo USBFABRIC_R05_USBIP_EXPORT=NOT_TESTED >/dev/console
echo USBFABRIC_R05_VHCI_IMPORT=NOT_TESTED >/dev/console
echo USBFABRIC_R05_EVDEV_REPORTS=NOT_TESTED >/dev/console
echo USBFABRIC_R04_GUEST_PROBE_END=YES >/dev/console
sync
poweroff -f || reboot -f
