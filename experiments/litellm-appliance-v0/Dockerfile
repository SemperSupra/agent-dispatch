ARG LITELLM_BASE=ghcr.io/berriai/litellm@sha256:bd089afdcd35b894b14a93f9743cdc8b591f82da1a38dd43a010a7b0c9de5fd7
FROM ${LITELLM_BASE}

LABEL org.opencontainers.image.title="SemperSupra LiteLLM Appliance" \
      org.opencontainers.image.description="Thin deployment appliance around pinned upstream LiteLLM" \
      org.opencontainers.image.vendor="SemperSupra" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="MIT" \
      com.sempersupra.litellm.upstream.version="v1.103.0" \
      com.sempersupra.litellm.upstream.commit="c991f4b01f5799eb0b0cab0fb63988e15c3a8a9d" \
      com.sempersupra.litellm.upstream.digest="sha256:bd089afdcd35b894b14a93f9743cdc8b591f82da1a38dd43a010a7b0c9de5fd7" \
      com.sempersupra.contract.profile="gateway-minimal"

COPY --chmod=0555 appliances/litellm/semper-entrypoint.sh /usr/local/bin/semper-litellm-entrypoint


ENTRYPOINT ["/usr/local/bin/semper-litellm-entrypoint"]
CMD ["--config", "/config/proxy_server_config.yaml", "--port", "4000"]
