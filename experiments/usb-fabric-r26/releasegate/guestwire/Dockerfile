# syntax=docker/dockerfile:1.7
# Public, disposable, TEST-ONLY Linux evdev -> virtio-serial -> Go gate workcell.
ARG DEBIAN_BASE=debian:trixie-slim
ARG GO_BASE=golang:1.23-bookworm
FROM ${GO_BASE} AS go-builder
WORKDIR /src
COPY experiments/usb-fabric-r26/releasegate/ /src/
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
RUN go test -race -count=1 ./... && go vet ./... && \
    CGO_ENABLED=0 go build -trimpath -o /out/guestwire-observer ./guestwire/cmd/guest && \
    CGO_ENABLED=0 go build -trimpath -o /out/hostbridge ./guestwire/cmd/host && \
    CGO_ENABLED=0 go build -trimpath -o /out/r27-runtime-guest-observer ./guestwire/cmd/runtimeguest && \
    CGO_ENABLED=0 go build -trimpath -o /out/r27-provision ./guestwire/cmd/provision && \
    /out/r27-provision /out/r27-guest-private /out/r27-guest-public

FROM ${DEBIAN_BASE} AS kernel-builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY experiments/usb-fabric-r26/releasegate/guestwire/init.sh /src/init.sh
COPY --from=go-builder /out/guestwire-observer /src/guestwire-observer
COPY --from=go-builder /out/r27-runtime-guest-observer /src/r27-runtime-guest-observer
COPY --from=go-builder /out/r27-guest-private /src/r27-guest-private
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    linux-image-amd64 initramfs-tools busybox-static cpio gzip kmod zstd xz-utils && \
    mkdir -p /out /tmp/extracted /tmp/repacked && \
    kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' | head -n 1)" && \
    test -n "$kernel" && cp "$kernel" /out/kernel && \
    version="${kernel#/boot/vmlinuz-}" && \
    printf 'evdev\nxhci_hcd\nxhci_pci\nusbhid\nhid_generic\nvirtio\nvirtio_ring\nvirtio_pci\nvirtio_console\n' >> /etc/initramfs-tools/modules && \
    mkinitramfs -o /out/default-initrd "$version" && \
    unmkinitramfs /out/default-initrd /tmp/extracted && \
    if [ -d /tmp/extracted/main ]; then cp -a /tmp/extracted/main/. /tmp/repacked/; else cp -a /tmp/extracted/. /tmp/repacked/; fi && \
    cp /src/init.sh /tmp/repacked/init && chmod 0755 /tmp/repacked/init && \
    cp /src/guestwire-observer /tmp/repacked/guestwire-observer && chmod 0755 /tmp/repacked/guestwire-observer && \
    cp /src/r27-runtime-guest-observer /tmp/repacked/r27-runtime-guest-observer && chmod 0755 /tmp/repacked/r27-runtime-guest-observer && \
    mkdir -p /tmp/repacked/etc && cp /src/r27-guest-private /tmp/repacked/etc/r27-guest-private-key && chmod 0400 /tmp/repacked/etc/r27-guest-private-key && \
    find /tmp/repacked -type f -name '*.ko.zst' -exec zstd -q -d --rm {} + && \
    find /tmp/repacked -type f -name '*.ko.xz' -exec xz -q -d {} + && \
    depmod -b /tmp/repacked "$version" && \
    mkdir -p /tmp/repacked/bin && cp /bin/busybox /tmp/repacked/bin/busybox && \
    cd /tmp/repacked && find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /out/initrd.gz && \
    sha256sum /out/kernel /out/initrd.gz && test -s /out/initrd.gz

FROM ${DEBIAN_BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    qemu-system-x86 python3 && rm -rf /var/lib/apt/lists/*
COPY --from=kernel-builder /out/kernel /guest/kernel
COPY --from=kernel-builder /out/initrd.gz /guest/initrd.gz
COPY --from=go-builder /out/hostbridge /guest/r26-hostbridge
COPY --from=go-builder /out/r27-guest-public /guest/r27-guest-public
COPY experiments/usb-fabric-r26/releasegate/guestwire/oracle.py /guest/oracle.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/oracle.py"]
