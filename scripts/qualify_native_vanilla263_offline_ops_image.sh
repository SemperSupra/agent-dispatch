#!/usr/bin/env bash
# Source-level preflight of the exact disposable G4 synthetic OP conversion.
# Does not launch Minecraft, a TrueNAS guest, or an operational server.
set -euo pipefail
IMAGE='ghcr.io/itzg/minecraft-server:2026.10.0-java25@sha256:5a2ab74ae179c11e2dbbce67f307cdcf2c1257b3abb0f654d3a310b3d8ea57da'
UUID='f4469b77-cc14-3c07-95f3-0b0c3f151bd2'
NAME='SupraCraftProbe'
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v docker >/dev/null || { echo 'PRECHECK_DOCKER_MISSING'; exit 2; }
command -v python3 >/dev/null || { echo 'PRECHECK_PYTHON_MISSING'; exit 2; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/out"
python3 - "$ROOT" "$UUID" "$NAME" <<'PY'
import hashlib, pathlib, sys, uuid
root,expected,name=sys.argv[1:]
value=str(uuid.UUID(bytes=hashlib.md5(("OfflinePlayer:"+name).encode()).digest(),version=3))
assert value==expected, "synthetic offline identity changed"
src=(pathlib.Path(root)/"scripts/qualify_native_vanilla263_loopback_player_overlay.py").read_text()
assert f'BOT_OFFLINE_UUID = "{expected}"' in src, "disposable overlay drift"
assert 'mc["ops"] = [BOT_OFFLINE_UUID]' in src, "unresolved username used as OPS"
PY
# No platform or provider credentials; no raw container startup logs/identities.
# Bounded actual pinned-image helper: do not substitute a source-only JSON mock.
timeout 240s docker pull "$IMAGE" >/dev/null 2>&1 || {
  echo 'IMAGE_PULL_NOT_QUALIFIED'; exit 2;
}
timeout 90s docker run --rm --network none --user 0:0 \
  -e ONLINE_MODE=FALSE -v "$tmp/out:/out" \
  --entrypoint mc-image-helper "$IMAGE" \
  manage-users --type=JAVA_OPS --version=26.3 \
  --existing=SYNCHRONIZE --output-directory=/out "$UUID" \
  >/dev/null 2>&1 || {
  echo 'PINNED_OFFLINE_UUID_IMAGE_HELPER_REFUSED'; exit 2;
}
python3 - "$tmp/out/ops.json" "$UUID" <<'PY'
import json, pathlib, sys, uuid
p=pathlib.Path(sys.argv[1])
assert p.is_file() and 0 < p.stat().st_size < 8192, "no bounded operators file"
doc=json.loads(p.read_text())
assert type(doc) is list and len(doc)==1, "not exactly one synthetic OP"
entry=doc[0]
assert type(entry) is dict and uuid.UUID(entry["uuid"])==uuid.UUID(sys.argv[2]), "wrong offline identity"
assert entry["level"]==4 and entry["bypassesPlayerLimit"] is False, "unexpected operator privileges"
PY
echo 'PINNED_OFFLINE_UUID_IMAGE_HELPER_SOURCE_QUALIFIED'
