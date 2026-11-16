# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:1.24-bookworm
FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY main.go ./
RUN --network=none --mount=type=tmpfs,target=/tmp \
    mkdir -p /out && \
    CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOENV=off GOTOOLCHAIN=local go build -trimpath -ldflags="-s -w -X main.allowedMode=broker" -o /out/broker ./main.go && \
    CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOENV=off GOTOOLCHAIN=local go build -trimpath -ldflags="-s -w -X main.allowedMode=client" -o /out/client ./main.go && \
    CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOENV=off GOTOOLCHAIN=local go build -trimpath -ldflags="-s -w -X main.allowedMode=issuer" -o /out/issuer ./main.go
FROM scratch AS broker
COPY --from=builder /out/broker /broker
USER 65532:65532
ENTRYPOINT ["/broker","serve"]
FROM scratch AS client
COPY --from=builder /out/client /client
USER 65532:65532
ENTRYPOINT ["/client","client"]
FROM scratch AS issuer
COPY --from=builder /out/issuer /issuer
USER 65532:65532
ENTRYPOINT ["/issuer"]
