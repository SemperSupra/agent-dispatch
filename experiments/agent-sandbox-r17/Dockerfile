# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:1.24-bookworm
ARG QEMU_IMAGE=ubuntu:24.04
FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod main.go main_test.go ./
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOENV=off GOCACHE=/tmp/gocache
RUN --network=none --mount=type=tmpfs,target=/tmp \
    go test -race -count=1 -v ./... && go vet ./... && \
    mkdir -p /out && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.role=broker" -o /out/broker . && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.role=client" -o /out/client .
FROM ${QEMU_IMAGE} AS broker
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
    qemu-system-x86 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/broker /broker
USER 65532:65532
ENTRYPOINT ["/broker"]
FROM scratch AS client
COPY --from=builder /out/client /client
USER 65532:65532
ENTRYPOINT ["/client"]
