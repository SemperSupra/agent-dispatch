#!/usr/bin/env bash
set -Eeuo pipefail
CANDIDATE="${1:?candidate required}"
case "$CANDIDATE" in
  gallery)
    DIST='gallery-dl==1.32.19'
    WHEEL='gallery_dl-1.32.19-py3-none-any.whl'
    HASH='f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50'
    CLI='gallery-dl'
    ;;
  parth)
    DIST='parth-dl==1.2.1'
    WHEEL='parth_dl-1.2.1-py3-none-any.whl'
    HASH='3117e4c7bd6fe7c6f1b668d05c40c303e54fc3992019bf6a40ab13b98434ebff'
    CLI='parth-dl'
    ;;
  *) echo 'R36_UNSUPPORTED_CANDIDATE'; exit 2 ;;
esac
ROOT="$(cd "$(dirname "$0")" && pwd)"
EVIDENCE="${GITHUB_WORKSPACE:?}/winnow-g1-r36-evidence"
mkdir -p "$EVIDENCE"
TMP="$(mktemp -d /tmp/winnow-r36.XXXXXX)"
trap 'rm -rf -- "$TMP"' EXIT
chmod 0755 "$TMP"
python3 -m venv "$TMP/venv"
"$TMP/venv/bin/python" -m pip --version > "$EVIDENCE/pip-version.txt"
mkdir "$TMP/wheels"
"$TMP/venv/bin/python" -m pip --disable-pip-version-check download \
  --only-binary=:all: --no-deps --index-url https://pypi.org/simple \
  --dest "$TMP/wheels" "$DIST" > "$EVIDENCE/download.txt"
printf '%s  %s\n' "$HASH" "$TMP/wheels/$WHEEL" | sha256sum -c -
if [[ "$CANDIDATE" == gallery ]]; then
  "$TMP/venv/bin/python" -m pip --disable-pip-version-check download \
    --only-binary=:all: --index-url https://pypi.org/simple \
    --dest "$TMP/wheels" 'requests==2.32.5' >> "$EVIDENCE/download.txt"
fi
(cd "$TMP/wheels" && sha256sum -- * > "$EVIDENCE/wheel-closure-sha256.txt")
if [[ "$CANDIDATE" == gallery ]]; then
  "$TMP/venv/bin/python" -m pip --disable-pip-version-check install \
    --no-index --find-links "$TMP/wheels" 'requests==2.32.5' > "$EVIDENCE/install.txt"
fi
"$TMP/venv/bin/python" -m pip --disable-pip-version-check install \
  --no-index --no-deps --find-links "$TMP/wheels" "$DIST" >> "$EVIDENCE/install.txt"
"$TMP/venv/bin/python" -m pip freeze > "$EVIDENCE/installed-closure.txt"

# Network and runner privilege are needed only to install PUBLIC pinned wheels
# and create an EPHEMERAL netns on a disposable GitHub Actions runner. Neither
# package sees live source URLs, personal data, tokens nor network access.
PROBE="$TMP/cli_probe.py"
install -m 0644 "$ROOT/cli_probe.py" "$PROBE"
for executable in sudo unshare setpriv readlink; do
  if ! command -v "$executable" >/dev/null; then
    echo "R36_SETUP_BLOCKED missing=$executable"
    exit 2
  fi
done
if ! sudo -n unshare --net -- /bin/true; then
  echo 'R36_SETUP_BLOCKED network_namespace=NOT_AVAILABLE'
  exit 2
fi
HOST_NS="$(readlink /proc/self/ns/net)"
sudo -n unshare --net -- /usr/bin/setpriv \
  --reuid=65534 --regid=65534 --clear-groups \
  "$TMP/venv/bin/python" "$PROBE" "$HOST_NS" "$CANDIDATE" \
  "$TMP/venv/bin/$CLI" "$TMP/venv" | tee "$EVIDENCE/result.txt"
grep -F -- 'R36_PINNED_REAL_CLI_SANDBOX_PASS' "$EVIDENCE/result.txt"
echo "R36_BOUND_REAL_CLI_NO_NETWORK_PASS=$GITHUB_SHA candidate=$CANDIDATE"
