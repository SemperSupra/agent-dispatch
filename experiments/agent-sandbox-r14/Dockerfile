# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
ARG QEMU_PACKAGE
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    python3 "${QEMU_PACKAGE}" && rm -rf /var/lib/apt/lists/*
COPY usbredir_probe.py /app/usbredir_probe.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/app/usbredir_probe.py"]
