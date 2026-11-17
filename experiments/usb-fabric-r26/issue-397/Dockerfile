# syntax=docker/dockerfile:1.7
ARG R15_IMAGE
FROM ${R15_IMAGE} AS pcsc-builder
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
 cpio gzip gcc libc6-dev pcscd libccid libpcsclite-dev pkg-config && rm -rf /var/lib/apt/lists/*
COPY issue-397/init.sh issue-397/pcsc_probe.c /src/
RUN gcc -O2 -Wall -Wextra -o /tmp/r26-pcsc-probe /src/pcsc_probe.c \
  $(pkg-config --cflags --libs libpcsclite) && \
 mkdir -p /tmp/r26-initrd && cd /tmp/r26-initrd && \
 gzip -dc /guest/initrd.gz | cpio --quiet -idmu && \
 cp /src/init.sh ./init && chmod 0755 ./init && \
 cp /tmp/r26-pcsc-probe ./r26-pcsc-probe && chmod 0755 ./r26-pcsc-probe && \
 mkdir -p ./usr/sbin ./usr/lib/pcsc && \
 cp /usr/sbin/pcscd ./usr/sbin/pcscd && \
 cp -a /usr/lib/pcsc/drivers ./usr/lib/pcsc/ && \
 ( ldd /usr/sbin/pcscd; ldd /tmp/r26-pcsc-probe; \
 find /usr/lib/pcsc/drivers -name '*.so' -type f -exec ldd '{}' \; ) | \
 awk '{for(i=1;i<=NF;i++) if(substr($i,1,1)=="/") print $i}' | \
 sort -u | while read -r lib; do test -r "$lib" && cp -L --parents "$lib" /tmp/r26-initrd/ || exit 1;done && \
 find /usr/lib /lib -name 'libpcsclite_real.so*' -exec cp -L --parents '{}' /tmp/r26-initrd/ \; && \
 test -n "$(find /tmp/r26-initrd -name 'libpcsclite_real.so*' -print -quit)" && \
 find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /guest/r26-pcsc-initrd.gz && \
 test -s /guest/r26-pcsc-initrd.gz
FROM ${R15_IMAGE}
USER root
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y libnss3-tools && rm -rf /var/lib/apt/lists/*
COPY --from=pcsc-builder /guest/r26-pcsc-initrd.gz /guest/r26-pcsc-initrd.gz
COPY issue-394/probe.py /guest/r26-n5-probe.py
COPY issue-397/run.py /guest/r26-n5b-run.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-n5b-run.py"]
