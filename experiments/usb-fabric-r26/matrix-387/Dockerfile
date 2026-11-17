# syntax=docker/dockerfile:1.7
ARG R15_IMAGE
FROM ${R15_IMAGE} AS initrd-builder
USER root
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends cpio gzip gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY init.sh pointer_observer.c /src/
RUN mkdir -p /tmp/r26-initrd && cd /tmp/r26-initrd && \
  gzip -dc /guest/initrd.gz | cpio --quiet -idmu && \
  cp /src/init.sh ./init && chmod 0755 ./init && \
  gcc -Os -static -Wall -Wextra -o ./pointer_observer /src/pointer_observer.c && chmod 0755 ./pointer_observer && \
  find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /guest/r26-initrd.gz && test -s /guest/r26-initrd.gz
FROM ${R15_IMAGE}
COPY --from=initrd-builder /guest/r26-initrd.gz /guest/r26-initrd.gz
COPY run.py /guest/r26-m1-run.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-m1-run.py"]
