#!/usr/bin/env bash
set -euo pipefail
HOST="${1:?usage: r1-readonly-remote.sh <root@ssh-host-or-alias> [output-dir]}"
OUT="${2:-wrt-r1-$(date -u +%Y%m%dT%H%M%SZ)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE="/tmp/rdte-r1-$$"
mkdir -p "$OUT"
ssh -o BatchMode=yes -o ConnectTimeout=8 "$HOST" "mkdir -p '$REMOTE' && sh -s -- '$REMOTE'" < "$ROOT/rdte/r1-readonly-collector.sh"
ssh -o BatchMode=yes "$HOST" "tar -C '$REMOTE' -czf - ." > "$OUT/r1-evidence.tar.gz"
tar -C "$OUT" -xzf "$OUT/r1-evidence.tar.gz"
ssh -o BatchMode=yes "$HOST" "rm -rf '$REMOTE'" || true
python3 "$ROOT/rdte/r1-reduce.py" "$OUT" -o "$OUT/device-descriptor.json"
python3 - "$OUT/device-descriptor.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d["write_authority"]=="DENIED_R1_READ_ONLY"
print(json.dumps({"ready_for_r2":bool(d.get("ready_for_r2")),
                  "write_authority":d["write_authority"],
                  "descriptor":sys.argv[1]},indent=2,sort_keys=True))
PY
