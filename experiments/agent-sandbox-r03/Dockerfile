# syntax=docker/dockerfile:1.7
# The distribution image is dynamically resolved by the ephemeral CI job to a
# sha256 digest and injected through BASE_IMAGE. No tools in deployed layer.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE} AS builder
ARG TARGET_TRIPLE
ARG TARGET_NAME
ARG TARGET_LIBC_PKG
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY target.c /src/target.c
RUN --mount=type=tmpfs,target=/tmp \
    apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    "gcc-${TARGET_TRIPLE}-linux-gnu" "libc6-dev-${TARGET_LIBC_PKG}-cross" qemu-user-static file && \
    "${TARGET_TRIPLE}-linux-gnu-gcc" -O2 -static \
    "-DTARGET_ARCH_NAME=\"${TARGET_NAME}\"" \
    -o /out-foreign /src/target.c && \
    file /out-foreign && \
    cp "/usr/bin/qemu-${TARGET_TRIPLE}-static" /out-qemu && \
    test -s /out-foreign && test -s /out-qemu

FROM scratch
COPY --from=builder /out-foreign /app
COPY --from=builder /out-qemu /qemu
USER 65532:65532
ENTRYPOINT ["/qemu", "/app"]
