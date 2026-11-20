# syntax=docker/dockerfile:1.7
# R27-G: original corrected R27-D Go module is SOURCE PINNED in the base
# builder; this layer changes only the real three-kernel test orchestration.
ARG PARENT
FROM ${PARENT}
COPY experiments/pi-usb-fabric-r27/typed-kernel-runtime/run.sh /guest/r27-b-run.sh
COPY experiments/pi-usb-fabric-r27/typed-kernel-runtime/qualify.sh /guest/r27-g-qualify.sh
USER 65532:65532
ENTRYPOINT ["/bin/sh","/guest/r27-g-qualify.sh"]
