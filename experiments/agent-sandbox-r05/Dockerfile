# syntax=docker/dockerfile:1.7
ARG BUILDER_IMAGE=golang:1.24-bookworm
FROM ${BUILDER_IMAGE} AS builder
WORKDIR /src
COPY probe.go /src/probe.go
RUN --mount=type=tmpfs,target=/tmp \
    mkdir -p /out && CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOENV=off \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/probe ./probe.go
FROM scratch
COPY --from=builder /out/probe /probe
USER 65532:65532
ENTRYPOINT ["/probe","serve"]
