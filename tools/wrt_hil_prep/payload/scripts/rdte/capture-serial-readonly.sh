#!/usr/bin/env bash
# Passive WRT serial capture: configures only the host-side TTY and reads bytes.
# Never writes serial payload bytes to the DUT.
set -euo pipefail

DEV="${1:?usage: capture_wrt_serial_readonly.sh <tty-device> [seconds] [output-dir]}"
DURATION="${2:-60}"
OUT="${3:-wrt-serial-$(date -u +%Y%m%dT%H%M%SZ)}"
HERE="$(cd "$(dirname "$0")" && pwd)"

case "$DURATION" in
  ''|*[!0-9]*) echo "duration must be an integer number of seconds" >&2; exit 2 ;;
esac
[ "$DURATION" -ge 1 ] || { echo "duration must be >=1" >&2; exit 2; }
[ -c "$DEV" ] || { echo "serial device is not a character device: $DEV" >&2; exit 2; }
command -v stty >/dev/null
command -v timeout >/dev/null
command -v sha256sum >/dev/null
command -v python3 >/dev/null

mkdir -p "$OUT"
TRANSCRIPT="$OUT/serial-transcript.log"
META="$OUT/serial-capture.json"

# Configure the local adapter only. With GND/RX/TX-only cabling and no flow control,
# this changes UART framing but does not intentionally transmit any payload byte.
stty -F "$DEV" 115200 cs8 -cstopb -parenb -ixon -ixoff -crtscts raw -echo

start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
timeout "${DURATION}s" cat -- "$DEV" > "$TRANSCRIPT"
rc=$?
set -e
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
  echo "serial capture failed with rc=$rc" >&2
  exit "$rc"
fi
end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
bytes="$(wc -c < "$TRANSCRIPT" | tr -d ' ')"
sha="$(sha256sum "$TRANSCRIPT" | awk '{print $1}')"

python3 - "$META" "$DEV" "$DURATION" "$start" "$end" "$bytes" "$sha" <<'PY'
import json,sys
path,device,duration,start,end,byte_count,sha=sys.argv[1:]
with open(path,"w") as f:
    json.dump({
      "schema":"rdte-wrt-serial-capture/v1",
      "authority":"SENSOR_ONLY_NO_ACTUATION",
      "device":device,
      "baud":115200,
      "framing":"8N1",
      "flow_control":"none",
      "duration_seconds":int(duration),
      "captured_utc_start":start,
      "captured_utc_end":end,
      "bytes_captured":int(byte_count),
      "transcript_sha256":sha,
      "serial_payload_bytes_transmitted":0,
      "dtr_enabled":False,
      "rts_enabled":False
    },f,indent=2,sort_keys=True)
    f.write("\n")
PY

for parser in "$HERE/parse_wrt_serial_transcript.py" "$HERE/serial-observe.py"; do
  if [ -f "$parser" ]; then
    python3 "$parser" "$TRANSCRIPT" -o "$OUT/serial-observation.json"
    break
  fi
done

printf '%s\n' "$OUT"
