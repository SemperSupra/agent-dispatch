# syntax=docker/dockerfile:1.7
# Overlay the unchanged source-qualified R22 real three-kernel USBIP image.
# Upstream QEMU-maintained read-only qemu.qmp is an RDTE observer, NOT a
# second QMP actuator, broker, or trusted USB/IP export authority.
ARG PARENT
FROM ${PARENT}
USER root
RUN set -eux; \
    echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/trixie-backports.list; \
    apt-get update -qq; \
    apt-get install -y --no-install-recommends -t trixie-backports python3-qemu-qmp=0.0.6-1~bpo13+1; \
    /usr/bin/python3 -c 'from qemu.qmp import QMPClient; print("R25_B_QEMU_UPSTREAM_LIBRARY_IMPORT=PASS")'; \
    rm -rf /var/lib/apt/lists/*
COPY experiments/pi-usb-fabric-r25/qmp-usbip-vm-observer/run.sh /guest/r25-run.sh
COPY experiments/pi-usb-fabric-r25/qmp-usbip-vm-observer/qmp_observer.py /guest/r25-qmp-observer.py
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/r25-run.sh"]
