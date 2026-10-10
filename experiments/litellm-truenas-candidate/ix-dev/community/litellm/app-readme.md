# LiteLLM

LiteLLM provides an OpenAI-compatible gateway over multiple model providers.

This package uses the SemperSupra LiteLLM appliance, which is pinned to an exact signed upstream release and adds only protected file-to-environment secret projection before starting the upstream LiteLLM entrypoint.

## Required storage

The config host directory must contain `proxy_server_config.yaml`.

The provider-secret host directory may contain files such as `DEEPSEEK_API_KEY`. Each filename must be a valid uppercase environment-variable name. Values are read only inside the container at process start.
