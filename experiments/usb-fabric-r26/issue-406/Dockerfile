# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE} AS guest-builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY init.sh /src/init.sh
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
 linux-image-amd64 initramfs-tools busybox-static cpio gzip kmod zstd xz-utils \
 genisoimage && \
 mkdir -p /out/discs /tmp/extracted /tmp/repacked /tmp/iso-root && \
 kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' | head -n 1)" && \
 test -n "$kernel" && cp "$kernel" /out/kernel && \
 version="${kernel#/boot/vmlinuz-}" && \
 printf "xhci_hcd\nxhci_pci\nscsi_mod\nusb_storage\nuas\nsr_mod\ncdrom\niso9660\nudf\n" >> /etc/initramfs-tools/modules && \
 mkinitramfs -o /out/default-initrd "$version" && \
 unmkinitramfs /out/default-initrd /tmp/extracted && \
 if [ -d /tmp/extracted/main ];then cp -a /tmp/extracted/main/. /tmp/repacked/;else cp -a /tmp/extracted/. /tmp/repacked/;fi && \
 cp /src/init.sh /tmp/repacked/init && chmod 0755 /tmp/repacked/init && \
 find /tmp/repacked -type f -name '*.ko.zst' -exec zstd -q -d --rm '{}' + && \
 find /tmp/repacked -type f -name '*.ko.xz' -exec xz -q -d '{}' + && \
 depmod -b /tmp/repacked "$version" && \
 mkdir -p /tmp/repacked/bin && cp /bin/busybox /tmp/repacked/bin/busybox && \
 printf 'R26_SYNTHETIC_OPTICAL_ISO_2026\n' > /tmp/iso-root/manifest.txt && \
 genisoimage -quiet -R -J -o /out/discs/iso9660.iso /tmp/iso-root && \
 printf 'R26_SYNTHETIC_OPTICAL_UDF_2026\n' > /tmp/iso-root/manifest.txt && \
 genisoimage -quiet -udf -R -J -o /out/discs/udf.iso /tmp/iso-root && \
 cd /tmp/repacked && find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /out/r26-optical-initrd.gz && \
 test -s /out/r26-optical-initrd.gz
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y qemu-system-x86 python3 && rm -rf /var/lib/apt/lists/*
COPY --from=guest-builder /out/kernel /guest/kernel
COPY --from=guest-builder /out/r26-optical-initrd.gz /guest/r26-optical-initrd.gz
COPY --from=guest-builder /out/discs /guest/discs
COPY run.py /guest/run.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/run.py"]
