# syntax=docker/dockerfile:1.7
ARG R15_IMAGE
FROM ${R15_IMAGE} AS initrd-builder
USER root
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y cpio gzip e2fsprogs && rm -rf /var/lib/apt/lists/*
COPY init.sh /src/init.sh
RUN mkdir -p /tmp/r26-initrd && cd /tmp/r26-initrd && \
 gzip -dc /guest/initrd.gz | cpio --quiet -idmu && \
 cp /src/init.sh ./init && chmod 0755 ./init && \
 mkdir -p ./usr/sbin && cp /usr/sbin/mkfs.ext4 ./usr/sbin/mkfs.ext4 && \
 ldd /usr/sbin/mkfs.ext4 | awk '/=> \\/\// {print $3} /^[[:space:]]*\\// {print $1}' | \
   while read -r lib;do test -r "$lib" && cp -L --parents "$lib" /tmp/r26-initrd/ || exit 1;done && \
 find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /guest/r26-initrd.gz && \
 test -s /guest/r26-initrd.gz
FROM ${R15_IMAGE}
COPY --from=initrd-builder /guest/r26-initrd.gz /guest/r26-initrd.gz
COPY run.py /guest/r26-n2-run.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-n2-run.py"]
