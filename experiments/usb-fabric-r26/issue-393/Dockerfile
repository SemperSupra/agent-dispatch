# syntax=docker/dockerfile:1.7
ARG GO_BASE=golang:1.23-bookworm
FROM ${GO_BASE}
WORKDIR /work
ENV DEBIAN_FRONTEND=noninteractive GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y gcc libxkbcommon-dev xkb-data && rm -rf /var/lib/apt/lists/*
COPY . /work/
RUN go test -race -count=1 ./... && go vet ./... && gcc -Wall -Wextra -Werror -o /usr/local/bin/r26-xkb-oracle xkb_oracle.c -lxkbcommon
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/r26-xkb-oracle"]
