# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE} AS builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY init.sh /src/init.sh
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    linux-image-amd64 initramfs-tools busybox-static cpio gzip kmod && \
    mkdir -p /out /tmp/extracted /tmp/repacked && \
    kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' | head -n 1)" && \
    test -n "$kernel" && cp "$kernel" /out/kernel && \
    version="${kernel#/boot/vmlinuz-}" && \
    mkinitramfs -o /out/default-initrd "$version" && \
    unmkinitramfs /out/default-initrd /tmp/extracted && \
    if [ -d /tmp/extracted/main ]; then cp -a /tmp/extracted/main/. /tmp/repacked/; else cp -a /tmp/extracted/. /tmp/repacked/; fi && \
    cp /src/init.sh /tmp/repacked/init && chmod 0755 /tmp/repacked/init && \
    mkdir -p /tmp/repacked/bin && cp /bin/busybox /tmp/repacked/bin/busybox && \
    cd /tmp/repacked && find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /out/initrd.gz && \
    sha256sum /out/kernel /out/initrd.gz && test -s /out/initrd.gz
FROM ${BASE_IMAGE} AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y qemu-system-x86 python3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/kernel /guest/kernel
COPY --from=builder /out/initrd.gz /guest/initrd.gz
COPY qmp_guest.py /guest/qmp_guest.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/qmp_guest.py"]
