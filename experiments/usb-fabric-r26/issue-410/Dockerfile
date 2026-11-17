# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
 pcscd vsmartcard-vpcd python3 python3-pyscard python3-cryptography && \
 rm -rf /var/lib/apt/lists/* && \
 test -n "$(find /usr/lib/pcsc -name 'libifdvpcd.so' -print -quit)"
COPY issue-398/test_card.py /test-card/base_card.py
COPY issue-410/pin_card.py /test-card/pin_card.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/test-card/pin_card.py"]
