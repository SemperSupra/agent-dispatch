# syntax=docker/dockerfile:1.7
# Entirely disposable public/free runner with genuine Linux guest /dev/tpm0.
ARG BASE=debian:trixie-slim
FROM ${BASE} AS kernel-builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY experiments/pi-usb-fabric-r24/guest-tpm/init.sh /src/init.sh
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
  linux-image-amd64 initramfs-tools busybox-static cpio gzip kmod zstd xz-utils \
  tpm2-tools libtss2-tcti-device0 coreutils && \
  mkdir -p /out /tmp/extracted /tmp/repacked && \
  kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' | head -n 1)" && \
  test -n "$kernel" && cp "$kernel" /out/kernel && \
  version="${kernel#/boot/vmlinuz-}" && \
  printf 'tpm\ntpm_tis\ntpm_tis_core\ntpm_crb\n' >> /etc/initramfs-tools/modules && \
  mkinitramfs -o /out/default-initrd "$version" && \
  unmkinitramfs /out/default-initrd /tmp/extracted && \
  if [ -d /tmp/extracted/main ]; then cp -a /tmp/extracted/main/. /tmp/repacked/; else cp -a /tmp/extracted/. /tmp/repacked/; fi && \
  cp /src/init.sh /tmp/repacked/init && chmod 0755 /tmp/repacked/init && \
  mkdir -p /tmp/repacked/bin /tmp/repacked/usr/bin /tmp/repacked/usr/lib/x86_64-linux-gnu && \
  cp /bin/busybox /tmp/repacked/bin/busybox && \
  for name in tpm2_getrandom tpm2_pcrread tpm2_createek tpm2_createak tpm2_flushcontext tpm2_quote tpm2_checkquote tpm2_pcrevent; do \
    cp "/usr/bin/$name" "/tmp/repacked/usr/bin/$name"; \
    ldd "/usr/bin/$name" | grep -Eo '/[^[:space:]]+' | \
      while read -r lib; do if test -f "$lib"; then mkdir -p "/tmp/repacked$(dirname "$lib")"; cp -L "$lib" "/tmp/repacked$lib"; fi; done; \
  done && \
  find /usr/lib/x86_64-linux-gnu -maxdepth 1 -name 'libtss2-tcti-device.so*' -exec cp -L --parents {} /tmp/repacked \; && \
  find /lib/x86_64-linux-gnu -maxdepth 1 -name 'libtss2-tcti-device.so*' -exec cp -L --parents {} /tmp/repacked \; && \
  find /tmp/repacked/usr/bin -name 'tpm2_*' | wc -l && \
  test "$(find /tmp/repacked/usr/bin -name 'tpm2_*' | wc -l)" -eq 8 && \
  find /tmp/repacked -type f -name '*.ko.zst' -exec zstd -q -d --rm {} + && \
  find /tmp/repacked -type f -name '*.ko.xz' -exec xz -q -d {} + && \
  depmod -b /tmp/repacked "$version" && \
  cd /tmp/repacked && find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /out/initrd.gz && \
  sha256sum /out/kernel /out/initrd.gz && test -s /out/initrd.gz

FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends \
 qemu-system-x86 swtpm python3 && rm -rf /var/lib/apt/lists/*
COPY --from=kernel-builder /out/kernel /guest/kernel
COPY --from=kernel-builder /out/initrd.gz /guest/initrd.gz
COPY experiments/pi-usb-fabric-r24/guest-tpm/oracle.py /guest/oracle.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/oracle.py"]
