# syntax=docker/dockerfile:1.7
# R27-B: final image extends the existing R26-A same-VM read-only QMP+VHCI
# harness; it only selects the source-scoped host-pin orchestration entry.
ARG PARENT
FROM ${PARENT}
COPY experiments/pi-usb-fabric-r27/usbip-hostpin/run.sh /guest/r27-b-run.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/r27-b-run.sh"]
