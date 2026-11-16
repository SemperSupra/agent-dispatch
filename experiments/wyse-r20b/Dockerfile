# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
 python3 qemu-system-x86 kmod linux-image-amd64 usbip && \
 rm -rf /var/lib/apt/lists/*
COPY probe.py /app/probe.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/app/probe.py"]
