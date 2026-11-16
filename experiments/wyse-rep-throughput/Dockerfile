# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}
COPY worker.sh /worker.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh","/worker.sh"]
