# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE} AS guest-builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src
COPY experiments/usb-fabric-r26/issue-414/init.sh /src/init.sh
COPY experiments/agent-sandbox-r15/hid_observer.c /src/hid_observer.c
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
 linux-image-amd64 initramfs-tools busybox-static cpio gzip kmod zstd xz-utils \
 alsa-utils libasound2 python3 gcc libc6-dev && \
 mkdir -p /out /tmp/extracted /tmp/repacked && \
 kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' | head -n 1)" && \
 test -n "$kernel" && cp "$kernel" /out/kernel && \
 version="${kernel#/boot/vmlinuz-}" && \
 printf "xhci_hcd\nxhci_pci\nusb_storage\nscsi_mod\nsd_mod\nusbhid\nhid_generic\nevdev\nusbnet\nrndis_host\ncdc_ether\nsnd\nsnd_pcm\nsnd_usb_audio\nsnd_usbmidi_lib\n" >> /etc/initramfs-tools/modules && \
 mkinitramfs -o /out/default-initrd "$version" && \
 unmkinitramfs /out/default-initrd /tmp/extracted && \
 if [ -d /tmp/extracted/main ];then cp -a /tmp/extracted/main/. /tmp/repacked/;else cp -a /tmp/extracted/. /tmp/repacked/;fi && \
 cp /src/init.sh /tmp/repacked/init && chmod 0755 /tmp/repacked/init && \
 find /tmp/repacked -type f -name '*.ko.zst' -exec zstd -q -d --rm '{}' + && \
 find /tmp/repacked -type f -name '*.ko.xz' -exec xz -q -d '{}' + && \
 depmod -b /tmp/repacked "$version" && \
 mkdir -p /tmp/repacked/bin /tmp/repacked/usr/bin /tmp/repacked/usr/share && \
 cp /bin/busybox /tmp/repacked/bin/busybox && \
 gcc -static -Os -Wall -Wextra -o /tmp/repacked/hid_observer /src/hid_observer.c && chmod 0755 /tmp/repacked/hid_observer && \
 cp /usr/bin/aplay /tmp/repacked/usr/bin/aplay && \
 cp -a /usr/share/alsa /tmp/repacked/usr/share/alsa && \
 ldd /usr/bin/aplay | awk '{for(i=1;i<=NF;i++)if(substr($i,1,1)=="/")print $i}' | \
 sort -u | while read -r lib;do test -r "$lib" && cp -L --parents "$lib" /tmp/repacked/ || exit 1;done && \
 python3 -c 'import wave,math,struct; f=wave.open("/tmp/repacked/r26-tone.wav","wb");f.setnchannels(2);f.setsampwidth(2);f.setframerate(44100);f.writeframes(b"".join(struct.pack("<hh",int(11000*math.sin(2*math.pi*440*i/44100)),int(11000*math.sin(2*math.pi*440*i/44100)))for i in range(44100)));f.close()' && \
 cd /tmp/repacked && find . -print | LC_ALL=C cpio --quiet -o -H newc | gzip -9 > /out/r26-fourarm-initrd.gz && \
 test -s /out/r26-fourarm-initrd.gz
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y qemu-system-x86 python3 && rm -rf /var/lib/apt/lists/*
COPY --from=guest-builder /out/kernel /guest/kernel
COPY --from=guest-builder /out/r26-fourarm-initrd.gz /guest/r26-fourarm-initrd.gz
COPY experiments/usb-fabric-r26/issue-405/run.py /guest/run.py
COPY experiments/usb-fabric-r26/issue-414/run.py /guest/r26-p8-run.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-p8-run.py"]
