# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE} AS builder
ARG TARGET
ARG TARGET_LIBC
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY workload.c .
RUN --mount=type=tmpfs,target=/tmp \
    apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    gcc libc6-dev "gcc-${TARGET}-linux-gnu" "libc6-dev-${TARGET_LIBC}-cross" qemu-user-static && \
    mkdir -p /out && \
    gcc -O2 -static -DTARGET_LABEL='"native-x86_64"' -o /out/native workload.c && \
    "${TARGET}-linux-gnu-gcc" -O2 -static "-DTARGET_LABEL=\"${TARGET}\"" -o /out/foreign workload.c && \
    cp "/usr/bin/qemu-${TARGET}-static" /out/qemu && \
    test -s /out/native && test -s /out/foreign && test -s /out/qemu
FROM scratch
COPY --from=builder /out/native /native
COPY --from=builder /out/foreign /foreign
COPY --from=builder /out/qemu /qemu
USER 65532:65532
ENTRYPOINT ["/native"]
