# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=golang:1.24-bookworm
FROM ${GO_IMAGE} AS testbuilder
WORKDIR /src
COPY go.mod lease.go lease_test.go ./
ENV GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOCACHE=/tmp/gocache
RUN --network=none --mount=type=tmpfs,target=/tmp \
    go test -race -count=1 -v ./... && \
    go vet ./... && \
    mkdir -p /out && printf 'R08_SIGNED_SYNTHETIC_TEST_SUITE=PASS\n' > /out/proof
FROM scratch
COPY --from=testbuilder /out/proof /proof
