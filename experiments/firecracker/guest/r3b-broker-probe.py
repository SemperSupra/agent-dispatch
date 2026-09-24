#!/usr/bin/env python3
import hashlib
import http.client
import json
import os
import socket

CONFIG = "/tmp/r3b-config.json"
RESULT = "/tmp/r3b-result.json"

with open(CONFIG, "r", encoding="utf-8") as fh:
    cfg = json.load(fh)

token = cfg["capability"]
host = cfg["host"]
port = int(cfg["port"])
request = cfg["request"]
request_bytes = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
token_sha256 = hashlib.sha256(token.encode("utf-8")).hexdigest()

# The one-run capability is consumed into process memory and removed from the
# writable guest surface before any network call.
os.remove(CONFIG)

def post_once():
    conn = http.client.HTTPConnection(host, port, timeout=4)
    conn.request(
        "POST",
        "/v1/infer",
        body=request_bytes,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Content-Length": str(len(request_bytes)),
        },
    )
    response = conn.getresponse()
    body = response.read(8192)
    status = response.status
    conn.close()
    return status, body

first_status, first_body = post_once()
second_status, second_body = post_once()

def blocked(target_host, target_port):
    try:
        s = socket.create_connection((target_host, target_port), timeout=0.7)
    except OSError:
        return True
    else:
        s.close()
        return False

other_host_blocked = blocked(host, port + 1)
metadata_blocked = blocked("169.254.169.254", 80)

result = {
    "first_status": first_status,
    "second_status": second_status,
    "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
    "response_sha256": hashlib.sha256(first_body).hexdigest(),
    "replay_response_sha256": hashlib.sha256(second_body).hexdigest(),
    "token_sha256": token_sha256,
    "other_host_blocked": other_host_blocked,
    "metadata_blocked": metadata_blocked,
}

with open(RESULT, "w", encoding="utf-8") as fh:
    json.dump(result, fh, sort_keys=True)
    fh.write("\n")
    fh.flush()
    os.fsync(fh.fileno())
os.sync()

print(
    "FIRECRACKER_R3B_BROKER "
    f"first={first_status} second={second_status} "
    f"request_sha256={result['request_sha256']} "
    f"response_sha256={result['response_sha256']} "
    f"other_host_blocked={1 if other_host_blocked else 0} "
    f"metadata_blocked={1 if metadata_blocked else 0}",
    flush=True,
)

raise SystemExit(
    0
    if first_status == 200
    and second_status == 409
    and other_host_blocked
    and metadata_blocked
    else 29
)
