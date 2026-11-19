# syntax=docker/dockerfile:1.7
# Layered atop unchanged R22/R25-B real three-kernel USBIP + read-only QMP.
ARG PARENT
FROM ${PARENT}
USER root
COPY experiments/pi-usb-fabric-r26/qmp-vhci-domain/run.sh /guest/r26-run.sh
COPY experiments/pi-usb-fabric-r26/qmp-vhci-domain/qmp_pci.py /guest/r26-qmp-pci.py
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/r26-run.sh"]
