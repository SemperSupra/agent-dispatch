# syntax=docker/dockerfile:1.7
ARG P2_IMAGE
FROM ${P2_IMAGE} AS initrd-builder
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
 cpio gzip gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY experiments/usb-fabric-r26/issue-409/init.sh /src/init.sh
COPY experiments/agent-sandbox-r15/hid_observer.c /src/hid_observer.c
RUN mkdir -p /tmp/r26-mixed-initrd && cd /tmp/r26-mixed-initrd && \
 gzip -dc /guest/r26-p2-initrd.gz | cpio --quiet -idmu && \
 cp /src/init.sh ./init && chmod 0755 ./init && \
 gcc -static -Os -Wall -Wextra -o ./hid_observer /src/hid_observer.c && \
 chmod 0755 ./hid_observer && \
 find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /guest/r26-mixed-initrd.gz && \
 test -s /guest/r26-mixed-initrd.gz
FROM ${P2_IMAGE}
COPY --from=initrd-builder /guest/r26-mixed-initrd.gz /guest/r26-mixed-initrd.gz
COPY experiments/usb-fabric-r26/issue-409/run.py /guest/r26-p5-run.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-p5-run.py"]
