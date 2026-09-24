#!/usr/bin/env python3
import hashlib, os, platform, random, secrets, time

# This value intentionally belongs to the reusable template and is expected to
# duplicate. It must not be treated as a workcell/session identity.
template_nonce=f"{random.getrandbits(128):032x}"
print(
    f"FIRECRACKER_W3_TEMPLATE_READY template={template_nonce} python={platform.python_version()} pid={os.getpid()}",
    flush=True,
)

# Host snapshots here. The source is never resumed. Every clone begins with the
# mandatory reset phase below before any work is accepted.
time.sleep(0.10)

seed_material=os.urandom(32)
seed_hash=hashlib.sha256(seed_material).hexdigest()
random.seed(int.from_bytes(seed_material,"big"))
session_id=f"{random.getrandbits(128):032x}"
py_random=f"{random.getrandbits(128):032x}"
capability=secrets.token_hex(16)

# Work occurs only after reinitialization.
work_digest=hashlib.sha256(("work:"+session_id+":"+py_random).encode()).hexdigest()
print(
    "FIRECRACKER_W3_RESET "
    f"template={template_nonce} seed_sha256={seed_hash} session={session_id} "
    f"py_random={py_random} secrets={capability} work_digest={work_digest}",
    flush=True,
)
