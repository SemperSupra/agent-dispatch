# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=golang:1.24-bookworm
FROM ${BASE_IMAGE}
WORKDIR /src
COPY go.mod fence.go fence_test.go ./
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOENV=off GOCACHE=/tmp/gocache GOMODCACHE=/tmp/mod
USER 65532:65532
ENTRYPOINT ["go","test","-race","-count=1","-v"]
