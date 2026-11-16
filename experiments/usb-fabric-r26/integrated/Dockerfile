# syntax=docker/dockerfile:1.7
ARG GO_BASE=golang:1.23-bookworm
FROM ${GO_BASE} AS go-builder
WORKDIR /src
COPY experiments/usb-fabric-r26/integrated/ /src/
ENV GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
RUN go vet ./... && CGO_ENABLED=0 go build -trimpath -o /out/r26-broker .

ARG R15_IMAGE
FROM ${R15_IMAGE}
COPY --from=go-builder /out/r26-broker /guest/r26-broker
COPY experiments/usb-fabric-r26/integrated/orchestrator.py /guest/r26-orchestrator.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-orchestrator.py"]
