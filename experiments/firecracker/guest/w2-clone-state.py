#!/usr/bin/env python3
import os, platform, random, secrets, time

# Deliberately initialize application PRNG/session state before the snapshot.
# Reusing the same snapshot may duplicate this state even if the kernel CRNG
# receives VM-fork entropy on restore.
session_id=f"{random.getrandbits(128):032x}"
print(
    f"FIRECRACKER_W2_READY session={session_id} python={platform.python_version()} pid={os.getpid()}",
    flush=True,
)

# Bounded host-pause window. The snapshot is taken while this interpreter and
# its PRNG state are live.
time.sleep(0.10)

post_random=f"{random.getrandbits(128):032x}"
kernel_random=os.urandom(16).hex()
secrets_token=secrets.token_hex(16)
print(
    "FIRECRACKER_W2_CLONE "
    f"session={session_id} py_random={post_random} urandom={kernel_random} secrets={secrets_token}",
    flush=True,
)
