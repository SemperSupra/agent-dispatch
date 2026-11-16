# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:1.24-bookworm
FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod main.go main_test.go ./
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOENV=off GOCACHE=/tmp/gocache
RUN --network=none --mount=type=tmpfs,target=/tmp \
    go test -race -count=1 -v ./... && go vet ./... && \
    mkdir -p /out && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.role=gateway" -o /out/gateway . && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.role=client" -o /out/client .
FROM scratch AS gateway
COPY --from=builder /out/gateway /gateway
USER 65532:65532
ENTRYPOINT ["/gateway"]
FROM scratch AS client
COPY --from=builder /out/client /client
USER 65532:65532
ENTRYPOINT ["/client"]
