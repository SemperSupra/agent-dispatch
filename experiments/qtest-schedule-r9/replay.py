#!/usr/bin/env python3
"""Replay fixed legacy queue-selector schedules, no guest or queue submission."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qtest-replay"))
from replay import common, stop, Session, require

SCHEDULES = ("AABB", "ABAB", "ABBA", "BAAB", "BABA", "BBAA")

def execute(order, out):
    start = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix="qtest-order-") as td:
        root = Path(td)
        args = common(root, "qtest") + [
            "-qtest", f"unix:{root/'test'},server=on,wait=off",
            "-qmp", f"unix:{root/'qmp'},server=on,wait=off"]
        raw = out / (order + ".raw")
        sess = None
        with raw.open("wb") as log:
            proc = subprocess.Popen(args, stdout=log, stderr=log)
            try:
                sess = Session(root, proc)
                ids = sess.pci_id(6)
                require((ids["vendor"], ids["device"]) == (0x1af4, 0x1001), "PCI ID")
                sess.pci(6, 0x10, 0x1001)
                sess.pci(6, 4, 1, "w")
                require(sess.pci(6, 0x10) & ~3 == 0x1000, "BAR")
                # PFN=1 points inside disposable 64 MiB RAM. Explicitly zero
                # descriptor, available and used ring footprint. No notify,
                # DRIVER_OK, guest or data IO; only register observations.
                sess.qt("memset 0x1000 0x4000 0")
                sess.qt("outb 0x1012 0")
                sess.qt("outb 0x1012 1")
                sess.qt("outb 0x1012 3")
                def snapshot():
                    return [sess.qt("inw 0x100e"), sess.qt("inw 0x100c"),
                            sess.qt("inl 0x1008")]
                sess.qt("outw 0x100e 0")
                require(snapshot() == [0, 256, 0], "initial queue")
                require(sess.qt("inb 0x1012") == 3, "initial status")
                counts = {"A": 0, "B": 0}
                rows = []
                for actor in order:
                    before = snapshot()
                    if counts[actor] == 0:
                        action = "select"
                        sess.qt("outw 0x100e " + ("1" if actor == "A" else "0"))
                    elif actor == "A":
                        action = "write"
                        sess.qt("outl 0x1008 1")
                    else:
                        action = "read"
                        # The explicit PFN read is the B action, independently
                        # recorded from selector/size observations.
                        require(sess.qt("inl 0x1008") == before[2], "unstable read")
                    counts[actor] += 1
                    after = snapshot()
                    rows.append(dict(actor=actor, action=action, before=before, after=after))
                sess.qt("outw 0x100e 0")
                present = snapshot()
                sess.qt("outw 0x100e 1")
                absent = snapshot()
                status = sess.qt("inb 0x1012")
                sess.qt("outb 0x1012 0")
                reset_status = sess.qt("inb 0x1012")
                sess.qt("outw 0x100e 0")
                reset_present = snapshot()
                sess.cmd("quit")
                rc = proc.wait(timeout=8)
            finally:
                if sess:
                    sess.close()
                stop(proc)
        require(rc == 0, "QEMU exit")
    require(not root.exists(), "cleanup")
    receipt = dict(schedule=order, steps=rows, present=present, absent=absent,
                   status=status, reset_status=reset_status, reset_present=reset_present,
                   process_exit=rc, cleanup=True, elapsed_ns=time.monotonic_ns()-start,
                   raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest())
    (out / (order + ".json")).write_text(json.dumps(receipt, separators=(",", ":"))+"\n")
    print(json.dumps(receipt), flush=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new empty evidence directory")
    args = parser.parse_args()
    args.output.mkdir()
    failures = []
    for order in SCHEDULES:
        try:
            execute(order, args.output)
        except Exception as exc:
            failures.append(order)
            print(f"{order}: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    if failures:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
