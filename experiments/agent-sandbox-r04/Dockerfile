# syntax=docker/dockerfile:1.7
# Tools and Linux netboot input exist only inside disposable OCI build stages.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE} AS builder
ARG TARGET_TRIPLE
ARG TARGET_LIBC
ARG DEBIAN_ARCH
ARG KERNEL_SHA
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY init.c mkinitrd.py /src/
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    ca-certificates curl python3 \
    "gcc-${TARGET_TRIPLE}-linux-gnu" "libc6-dev-${TARGET_LIBC}-cross" && \
    mkdir -p /out && \
    "${TARGET_TRIPLE}-linux-gnu-gcc" -Os -static \
      -o /out/init /src/init.c && \
    python3 /src/mkinitrd.py /out/init /out/initrd.gz && \
    curl --fail --location --silent --show-error --retry 2 --connect-timeout 10 \
      --max-time 90 \
      "https://deb.debian.org/debian/dists/trixie/main/installer-${DEBIAN_ARCH}/current/images/netboot/debian-installer/${DEBIAN_ARCH}/linux" \
      --output /out/kernel && \
    echo "${KERNEL_SHA}  /out/kernel" | sha256sum --check --strict && \
    echo 'R04_OFFICIAL_DEBIAN_KERNEL_SHA256_MATCH=PASS'

FROM ${BASE_IMAGE} AS runtime
ARG QEMU_PACKAGE
ARG TARGET_NAME
ENV DEBIAN_FRONTEND=noninteractive
ENV R04_ARCH=${TARGET_NAME}
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    "${QEMU_PACKAGE}" && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/kernel /guest/kernel
COPY --from=builder /out/initrd.gz /guest/initrd.gz
COPY boot.sh /guest/boot.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh", "/guest/boot.sh"]
