# Public disposable two-kernel USB/IP HID qualification image.
ARG BASE=debian:trixie-slim
FROM ${BASE} AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
  linux-image-amd64 initramfs-tools kmod usbip gcc libc6-dev \
  busybox-static cpio gzip zstd xz-utils && mkdir -p /out /tmp/root /tmp/merged
COPY experiments/pi-usb-fabric-r11/handoff/provider.init /tmp/provider.init
COPY experiments/pi-usb-fabric-r11/handoff/consumer-a.init /tmp/consumer-a.init
COPY experiments/pi-usb-fabric-r11/handoff/consumer-b.init /tmp/consumer-b.init
COPY experiments/pi-usb-fabric-r06/transport/hid_evdev_observer.c /tmp/evdev.c
RUN set -eux; \
  kernel="$(find /boot -maxdepth 1 -name 'vmlinuz-*' -type f | head -1)"; \
  test -n "$kernel"; version="${kernel#/boot/vmlinuz-}"; \
  cp "$kernel" /out/kernel; cp "/boot/config-$version" /out/kernel-config; \
  printf 'usbip_core\nusbip_host\nvhci_hcd\nusbip_vudc\nlibcomposite\ndummy_hcd\nusb_f_hid\nusbhid\nhid_generic\nevdev\ne1000\n' >> /etc/initramfs-tools/modules; \
  mkinitramfs -o /out/default-initrd "$version"; \
  unmkinitramfs /out/default-initrd /tmp/root; \
  if test -d /tmp/root/main; then cp -a /tmp/root/main/. /tmp/merged/; else cp -a /tmp/root/. /tmp/merged/; fi; \
  mkdir -p /tmp/merged/bin; cp /bin/busybox /tmp/merged/bin/busybox; \
  find /tmp/merged -type f -name '*.ko.zst' -exec zstd -d --rm -q {} +; \
  find /tmp/merged -type f -name '*.ko.xz' -exec xz -d {} +; \
  for name in usbip usbipd; do bin="$(command -v "$name")"; test -x "$bin"; \
    mkdir -p "/tmp/merged$(dirname "$bin")"; cp -L "$bin" "/tmp/merged$bin"; \
    ldd "$bin" | grep -Eo '/[^[:space:]]+' | while read -r lib; do \
      mkdir -p "/tmp/merged$(dirname "$lib")"; cp -L "$lib" "/tmp/merged$lib"; done; done; \
  mkdir -p /tmp/merged/usr/bin; \
  gcc -static -Os -Wall -Wextra -o /tmp/merged/usr/bin/hid_evdev_observer /tmp/evdev.c; \
  echo R08_COPY_KERNEL_MODULE_DEPENDENCY_CLOSURE; \
  for m in usbip_core usbip_host vhci_hcd usbip_vudc libcomposite dummy_hcd usb_f_hid usbhid hid_generic evdev e1000; do \
    modprobe -S "$version" --show-depends "$m" | awk '$1=="insmod"{print $2}'; \
  done | sort -u | while IFS= read -r kofile; do \
    test -f "$kofile"; mkdir -p "/tmp/merged$(dirname "$kofile")"; cp -L "$kofile" "/tmp/merged$kofile"; \
  done; \
  test -d "/tmp/merged/lib/modules/$version"; \
  find "/tmp/merged/lib/modules/$version" -type f -name '*.ko*' | wc -l; \
  depmod -b /tmp/merged "$version"; \
  for role in provider consumer-a consumer-b; do cp "/tmp/$role.init" /tmp/merged/init; chmod 0755 /tmp/merged/init; \
    test -f /tmp/merged/init && test -x /tmp/merged/init; \
    ls -ld /tmp/merged/init /tmp/merged/lib /tmp/merged/lib/modules || true; \
    (cd /tmp/merged && find . -print | cpio --quiet -o -H newc | gzip -9) > "/out/$role.gz"; \
    gzip -t "/out/$role.gz"; \
    mkdir -p "/tmp/check-$role"; \
    (cd "/tmp/check-$role" && gzip -dc "/out/$role.gz" | cpio --quiet -idm); \
    test -x "/tmp/check-$role/init"; \
    test -d "/tmp/check-$role/lib/modules/$version"; \
    echo "R08_ARCHIVE_EXTRACTED_BOOT_FILES=$role"; \
  done; \
  test -s /out/provider.gz && test -s /out/consumer-a.gz && test -s /out/consumer-b.gz
FROM ${BASE}
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
  qemu-system-x86 coreutils grep && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/kernel /guest/kernel
COPY --from=builder /out/provider.gz /guest/provider.gz
COPY --from=builder /out/consumer-a.gz /guest/consumer-a.gz
COPY --from=builder /out/consumer-b.gz /guest/consumer-b.gz
COPY --from=builder /out/kernel-config /guest/kernel-config
COPY experiments/pi-usb-fabric-r11/handoff/run.sh /guest/run.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/run.sh"]
