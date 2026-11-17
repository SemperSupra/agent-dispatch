# syntax=docker/dockerfile:1.7
ARG GO_BASE=golang:1.23-bookworm
ARG R15_IMAGE
FROM ${GO_BASE} AS model
WORKDIR /src
COPY . /src
ENV GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
RUN go test -race -count=1 -v ./... && go vet ./...
FROM ${R15_IMAGE}
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -qq --no-install-recommends -y libnss3-tools && rm -rf /var/lib/apt/lists/*
COPY probe.py /guest/r26-n5-probe.py
COPY --from=model /src/apdu.go /guest/n5-apdu-model.go
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-n5-probe.py"]
