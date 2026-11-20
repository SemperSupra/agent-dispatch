# syntax=docker/dockerfile:1.7
# R27-F: same actual Linux provider/A/B release experiment, reused
# R27-B verified host-preboot Ed25519 QEMU guest and R27-A real UDC fence.
ARG PARENT
FROM ${PARENT}
COPY experiments/pi-usb-fabric-r27/udc-hostpin-composite/run.sh /guest/r27-f-run.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/r27-f-run.sh"]
