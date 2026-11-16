# syntax=docker/dockerfile:1.7
# The builder image is resolved to an immutable digest by the disposable CI job.
ARG BUILDER_IMAGE=golang:1.24-bookworm
FROM ${BUILDER_IMAGE} AS builder
WORKDIR /src
COPY service.go ./service.go
ENV GOCACHE=/tmp/gocache GOPATH=/tmp/gopath GOMODCACHE=/tmp/gomodcache
RUN --mount=type=tmpfs,target=/tmp \
    mkdir -p /out && CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOENV=off \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/service ./service.go

FROM scratch
COPY --from=builder /out/service /service
USER 65532:65532
EXPOSE 18081
ENTRYPOINT ["/service"]
