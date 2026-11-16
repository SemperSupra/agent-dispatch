# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:1.24-bookworm
ARG DEBIAN_IMAGE=debian:trixie-slim
FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod main.go main_test.go ./
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOENV=off GOCACHE=/tmp/gocache
RUN --network=none --mount=type=tmpfs,target=/tmp \
    go test -race -count=1 -v ./... && go vet ./... && \
    mkdir -p /out && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w" -o /out/gateway .
FROM ${DEBIAN_IMAGE} AS server
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y usbip && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/gateway /gateway
USER 65532:65532
ENTRYPOINT ["/gateway","server"]
FROM scratch AS client
COPY --from=builder /out/gateway /gateway
USER 65532:65532
ENTRYPOINT ["/gateway","client"]
