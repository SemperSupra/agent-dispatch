# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    qemu-system-x86 python3 && rm -rf /var/lib/apt/lists/*
COPY qmp_devices.py /r06/qmp_devices.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/r06/qmp_devices.py"]
