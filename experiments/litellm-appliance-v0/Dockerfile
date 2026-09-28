ARG LITELLM_BASE=ghcr.io/berriai/litellm@sha256:87f34979b9f8cb274fac90ca8a4fdda07d8480de22755562a26adeb95ce20d02
FROM ${LITELLM_BASE}

LABEL org.opencontainers.image.title="SemperSupra LiteLLM Appliance" \
      org.opencontainers.image.description="Thin deployment appliance around pinned upstream LiteLLM" \
      org.opencontainers.image.vendor="SemperSupra" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/SemperSupra/agent-dispatch" \
      com.sempersupra.litellm.upstream.version="v1.102.1" \
      com.sempersupra.litellm.upstream.commit="d09bbae1c6df463e425558f60d460437193635da" \
      com.sempersupra.litellm.upstream.digest="sha256:87f34979b9f8cb274fac90ca8a4fdda07d8480de22755562a26adeb95ce20d02" \
      com.sempersupra.contract.profile="gateway-minimal"

COPY --chmod=0555 semper-entrypoint.sh /usr/local/bin/semper-litellm-entrypoint

ENV SEMPER_SECRET_DIR=/run/secrets/semper-env

ENTRYPOINT ["/usr/local/bin/semper-litellm-entrypoint"]
CMD ["--config", "/config/proxy_server_config.yaml", "--port", "4000"]
