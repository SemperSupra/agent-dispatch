# Disposable public synthetic QEMU guest; no physical USB or host module operations.
ARG BASE=debian:trixie-slim
FROM ${BASE} AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends linux-image-amd64 initramfs-tools kmod usbip busybox-static cpio gzip zstd xz-utils && mkdir -p /out /tmp/root /tmp/merged
COPY experiments/pi-usb-fabric-r06/transport/init.sh /tmp/guest-init
RUN set -eux;  kernel="$(find /boot -maxdepth 1 -name 'vmlinuz-*' -type f | head -1)";  test -n "$kernel"; version="${kernel#/boot/vmlinuz-}";  cp "$kernel" /out/kernel;  cp "/boot/config-$version" /out/kernel-config;  printf 'usbip_core\nusbip_host\nvhci_hcd\nusbip_vudc\nlibcomposite\ndummy_hcd\nusb_f_hid\nusbhid\nhid_generic\nevdev\n' >> /etc/initramfs-tools/modules;  mkinitramfs -o /out/default-initrd "$version";  unmkinitramfs /out/default-initrd /tmp/root;  if test -d /tmp/root/main; then cp -a /tmp/root/main/. /tmp/merged/; else mkdir -p /tmp/merged; cp -a /tmp/root/. /tmp/merged/; fi;  cp /tmp/guest-init /tmp/merged/init; chmod 0755 /tmp/merged/init;  mkdir -p /tmp/merged/bin; cp /bin/busybox /tmp/merged/bin/busybox;  find /tmp/merged -type f -name '*.ko.zst' -exec zstd -d --rm -q {} +;  find /tmp/merged -type f -name '*.ko.xz' -exec xz -d {} +;  for name in usbip usbipd; do bin="$(command -v "$name")"; test -x "$bin"; mkdir -p "/tmp/merged$(dirname "$bin")"; cp -L "$bin" "/tmp/merged$bin"; ldd "$bin" | grep -Eo '/[^[:space:]]+' | while read -r lib; do mkdir -p "/tmp/merged$(dirname "$lib")"; cp -L "$lib" "/tmp/merged$lib"; done; done; depmod -b /tmp/merged "$version";  (cd /tmp/merged && find . -print | cpio --quiet -o -H newc | gzip -9) > /out/initrd.gz;  test -s /out/initrd.gz
FROM ${BASE}
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends qemu-system-x86 coreutils grep && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/kernel /guest/kernel
COPY --from=builder /out/initrd.gz /guest/initrd.gz
COPY --from=builder /out/kernel-config /guest/kernel-config
COPY experiments/pi-usb-fabric-r04/guest-kernel/run.sh /guest/run.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/run.sh"]
