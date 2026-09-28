#!/bin/sh
set -eu

secret_dir="${SEMPER_SECRET_DIR:-/run/secrets/semper-env}"

fail() {
  echo "semper-litellm-entrypoint: $*" >&2
  exit 78
}

if [ -e "$secret_dir" ]; then
  [ -d "$secret_dir" ] || fail "secret path exists but is not a directory"

  for secret_path in "$secret_dir"/*; do
    [ -e "$secret_path" ] || continue
    [ -f "$secret_path" ] || fail "secret entry is not a regular file: ${secret_path##*/}"
    [ ! -L "$secret_path" ] || fail "secret symlinks are not accepted: ${secret_path##*/}"

    name="${secret_path##*/}"
    case "$name" in
      ""|[!A-Z_]*|*[!A-Z0-9_]*)
        fail "invalid environment-variable secret filename: $name"
        ;;
    esac

    eval "already_set=\${$name+x}"
    [ "${already_set:-}" != x ] || fail "secret variable is already present in the environment: $name"

    value="$(cat "$secret_path")"
    case "$value" in
      *'
'*)
        fail "secret file contains an embedded newline: $name"
        ;;
    esac
    [ -n "$value" ] || fail "secret file is empty: $name"

    export "$name=$value"
    unset value already_set
  done
fi

exec /app/docker/prod_entrypoint.sh "$@"
