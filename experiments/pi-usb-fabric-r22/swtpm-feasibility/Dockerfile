# Disposable userspace QEMU TPM2/swtpm wiring experiment.
ARG BASE=debian:trixie-slim
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
  qemu-system-x86 swtpm python3 ca-certificates && \
  rm -rf /var/lib/apt/lists/*
COPY experiments/pi-usb-fabric-r22/swtpm-feasibility/probe.py /guest/probe.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/probe.py"]
