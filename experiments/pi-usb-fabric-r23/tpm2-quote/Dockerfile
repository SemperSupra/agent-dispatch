# R23-C: disposable upstream swtpm + TPM2 command quote critics.
# This exercises a SOFTWARE simulator from userspace, not a Linux guest TPM
# driver, hardware endorsement key or independently trusted attestation.
ARG BASE=debian:trixie-slim
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
  swtpm tpm2-tools libtss2-tcti-swtpm0 python3 ca-certificates bash coreutils && \
  rm -rf /var/lib/apt/lists/*
COPY experiments/pi-usb-fabric-r23/tpm2-quote/quote.sh /guest/quote.sh
USER 65532:65532
ENTRYPOINT ["/bin/bash","/guest/quote.sh"]
