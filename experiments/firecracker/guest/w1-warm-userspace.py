#!/usr/bin/env python3
import hashlib, json, os, platform, time

RESULT="/tmp/w1-result.json"
COUNTER_MAX=10
BLOCK_BYTES=1024*1024
ITERATIONS=64

print(
    f"FIRECRACKER_W1_READY counter=0 python={platform.python_version()} pid={os.getpid()}",
    flush=True,
)

# Give the host a bounded window to pause after READY. This sleep is intentionally
# part of the captured warm state; the first post-resume heartbeat proves execution
# continued rather than rebooting.
time.sleep(0.10)
for counter in range(1, COUNTER_MAX + 1):
    time.sleep(0.01)
    print(f"FIRECRACKER_W1_HEARTBEAT counter={counter}", flush=True)

block=bytes(((i*17+3)&0xff) for i in range(BLOCK_BYTES))
started=time.perf_counter_ns()
h=hashlib.sha256()
for _ in range(ITERATIONS):
    h.update(block)
digest=h.hexdigest()
work_ns=time.perf_counter_ns()-started

result={
    "counter":COUNTER_MAX,
    "python_version":platform.python_version(),
    "digest":digest,
    "work_ns":work_ns,
    "block_bytes":BLOCK_BYTES,
    "iterations":ITERATIONS,
}
with open(RESULT,"w",encoding="utf-8") as fh:
    json.dump(result,fh,sort_keys=True); fh.write("\n"); fh.flush(); os.fsync(fh.fileno())
os.sync()
print(
    f"FIRECRACKER_W1_WORK counter={COUNTER_MAX} work_ns={work_ns} digest={digest}",
    flush=True,
)
