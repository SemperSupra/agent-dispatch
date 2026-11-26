# syntax=docker/dockerfile:1.7
ARG GO_BASE=golang:1.23-bookworm
ARG R15_IMAGE
FROM ${GO_BASE} AS go-builder
WORKDIR /src/integrated
COPY experiments/usb-fabric-r26/integrated/ /src/integrated/
COPY experiments/usb-fabric-r26/releasegate/ /src/releasegate/
ENV GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
RUN go test ./... && go vet ./... && CGO_ENABLED=0 go build -trimpath -o /out/r26-broker . && CGO_ENABLED=0 go build -trimpath -o /out/r26-actuator ./cmd/actuator && CGO_ENABLED=0 go build -trimpath -o /out/r26-frontend ./cmd/frontend && CGO_ENABLED=0 go build -trimpath -o /out/r26ctl ./cmd/controlcli

FROM ${R15_IMAGE}
COPY --from=go-builder /out/r26-broker /guest/r26-broker
COPY --from=go-builder /out/r26-actuator /guest/r26-actuator
COPY --from=go-builder /out/r26-frontend /guest/r26-frontend
COPY --from=go-builder /out/r26ctl /guest/r26ctl
COPY experiments/usb-fabric-r26/integrated/orchestrator.py /guest/r26-orchestrator.py
COPY experiments/usb-fabric-r26/integrated/actuator_oracle.py /guest/r26-actuator-oracle.py
COPY experiments/usb-fabric-r26/integrated/actuator_restart_oracle.py /guest/r26-actuator-restart-oracle.py
COPY experiments/usb-fabric-r26/integrated/l5_missing_journal_oracle.py /guest/r26-l5-missing-journal-oracle.py
COPY experiments/usb-fabric-r26/integrated/l6_dual_qmp_owner_oracle.py /guest/r26-l6-dual-qmp-owner-oracle.py
COPY experiments/usb-fabric-r26/integrated/l7_alternate_journal_oracle.py /guest/r26-l7-alternate-journal-oracle.py
COPY experiments/usb-fabric-r26/integrated/l9b_guest_readmission_oracle.py /guest/r26-l9b-guest-readmission-oracle.py
COPY experiments/usb-fabric-r26/integrated/l9c_scoped_release_detach_oracle.py /guest/r26-l9c-scoped-release-detach-oracle.py
COPY experiments/usb-fabric-r26/integrated/l10_lockfile_inode_oracle.py /guest/r26-l10-lockfile-inode-oracle.py
COPY experiments/usb-fabric-r26/integrated/r27c_signed_guest_oracle.py /guest/r27c_signed_guest_oracle.py
COPY experiments/usb-fabric-r26/integrated/r27_broker_cli_oracle.py /guest/r27-broker-cli-oracle.py
COPY experiments/usb-fabric-r26/integrated/r27d_readonly_oracle.py /guest/r27d_readonly_oracle.py
COPY experiments/usb-fabric-r26/integrated/r27e_joint_signed_cli_oracle.py /guest/r27e_joint_signed_cli_oracle.py
COPY experiments/usb-fabric-r26/integrated/r27f_wrong_pinned_key_oracle.py /guest/r27f_wrong_pinned_key_oracle.py
COPY experiments/usb-fabric-r26/integrated/protected_signed_hid_oracle.py /guest/protected_signed_hid_oracle.py
USER 65532:65532
ENTRYPOINT ["python3","-B","/guest/r26-orchestrator.py"]
