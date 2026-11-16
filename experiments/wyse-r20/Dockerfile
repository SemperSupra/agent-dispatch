# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=golang:1.24-bookworm
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y usbip && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod usbip.go usbip_test.go ./
ENV GOPROXY=off GOSUMDB=off GOENV=off GOTOOLCHAIN=local GOCACHE=/tmp/gocache GOMODCACHE=/tmp/mod
USER 65532:65532
ENTRYPOINT ["go","test","-race","-count=1","-v"]
