# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    python3 usbip && rm -rf /var/lib/apt/lists/*
COPY mock_usbip.py /app/mock_usbip.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/app/mock_usbip.py"]
