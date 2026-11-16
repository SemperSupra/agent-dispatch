# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=golang:1.24-bookworm
FROM ${BASE_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y \
 qemu-system-x86 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod qmp.go qmp_test.go ./
COPY --from=r19 /experiments/wyse-r19/go.mod /src/r19/go.mod
COPY --from=r19 /experiments/wyse-r19/fence.go /src/r19/fence.go
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOENV=off GOCACHE=/tmp/gocache GOMODCACHE=/tmp/mod
USER 65532:65532
ENTRYPOINT ["go","test","-race","-count=1","-v"]
