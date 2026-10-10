# LiteLLM

SemperSupra-qualified TrueNAS catalog-shaped package for the `gateway-minimal` LiteLLM appliance.

The application consumes:

- a read-only config directory containing `proxy_server_config.yaml`;
- a read-only provider-secret directory containing one file per environment variable.

The provider-secret directory is projected into the LiteLLM process by the SemperSupra appliance entrypoint. The OpenRouter management credential is explicitly outside this runtime boundary.
