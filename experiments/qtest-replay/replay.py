#!/usr/bin/env python3
"""Fresh disposable QTest and real TCG guest observations, public fixtures only."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from qtest_semantic_smoke import Session, require

def common(root, accel):
    disk = root / "data.raw"
    with disk.open("wb") as f:
        f.truncate(4 * 1024 * 1024)
    return ["qemu-system-x86_64", "-machine", f"q35,accel={accel}",
            "-nodefaults", "-display", "none", "-m", "64",
            "-drive", f"if=none,id=disk,format=raw,file={disk}",
            "-device", "virtio-blk-pci,drive=disk,id=blk,disable-modern=on,num-queues=1,addr=06.0"]

def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

def qtest(root, operations, rawpath):
    args = common(root, "qtest") + [
        "-qtest", f"unix:{root/'test'},server=on,wait=off",
        "-qmp", f"unix:{root/'qmp'},server=on,wait=off"]
    s = None
    with (root / "qemu.log").open("wb") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=log)
        try:
            s = Session(root, proc)
            ids = s.pci_id(6)
            require((ids.get("vendor"), ids.get("device")) == (0x1af4, 0x1001), f"PCI identity: {ids}")
            print(json.dumps({"qmp_pci_id": ids}), flush=True)
            s.pci(6, 0x10, 0x1001)
            s.pci(6, 4, 1, "w")
            require(s.pci(6, 0x10) & ~3 == 0x1000, "BAR")
            s.qt("outb 0x1012 0")
            s.qt("outb 0x1012 1")
            s.qt("outb 0x1012 3")
            s.qt("outw 0x100e 0")
            require(s.qt("inb 0x1012") == 3 and s.qt("inw 0x100c") == 256
                    and s.qt("inl 0x1008") == 0, "initial fixture state")
            observations = []
            ports = {0x1008: 4, 0x100c: 2, 0x100e: 2, 0x1010: 2, 0x1012: 1}
            for i, op in enumerate(operations):
                p, w = op["port"], op["width"]
                require(ports.get(p) == w, "outside fixed synthetic fixture")
                suffix = {1:"b", 2:"w", 4:"l"}[w]
                if op["kind"] == "pio-read":
                    v = s.qt(f"in{suffix} {p:#x}")
                    observations.append({"operation_index": i, "value": v})
                elif op["kind"] == "pio-write":
                    require(0 <= op["value"] < (1 << (w*8)), "write bounds")
                    s.qt(f"out{suffix} {p:#x} {op['value']:#x}")
                else:
                    raise ValueError("unsupported operation")
            s.cmd("quit")
            rc = proc.wait(timeout=8)
            require(rc == 0, "qtest clean exit")
            rawpath.write_bytes((root / "qemu.log").read_bytes())
            return observations, rc
        finally:
            if s:
                s.close()
            stop(proc)

def guest(root, boot, rawpath):
    # Guest boot instructions are independent of the model/translator.
    bootimg = root / "boot.raw"
    code = boot.read_bytes()
    require(len(code) == 512 and code[-2:] == b"\x55\xaa", "boot image")
    with bootimg.open("wb") as f:
        f.write(code)
        f.truncate(4 * 1024 * 1024)
    obs = root / "guest.bin"
    args = common(root, "tcg") + [
        "-drive", f"if=ide,index=0,format=raw,file={bootimg}",
        "-boot", "order=c,strict=on", "-serial", "none", "-monitor", "none",
        "-net", "none", "-no-reboot",
        "-chardev", f"file,id=obs,path={obs}",
        "-device", "isa-debugcon,iobase=0xe9,chardev=obs",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    with (root / "guest.log").open("wb") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=log)
        try:
            rc = proc.wait(timeout=20)
            require(rc == 33, f"guest exit {rc}: { (root/'guest.log').read_text(errors='replace')[-3000:] }")
            data = obs.read_bytes()
            rawpath.write_bytes(data)
            require(len(data) == 44, f"unexpected guest witness bytes {data.hex()}")
            words = struct.unpack("<11I", data)
            require(words[:6] == (0x35454856, 0x10011af4, 0x1001, 3, 256, 0),
                    f"guest fixture preconditions {words[:6]}")
            return [{"operation_index": i, "value": v}
                    for i, v in zip((1,3,5,7,8),words[6:])], rc
        finally:
            stop(proc)

def main():
    mode, planpath, bootpath, outdir = sys.argv[1:]
    require(mode in ("qtest","tcg-guest"), "vantage")
    p = Path(planpath).read_bytes()
    plan = json.loads(p)
    operations = plan["proposal"]["operations"]
    require(len(operations) == 9, "fixed proposal")
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    for i in range(8):
        start = time.monotonic_ns()
        with tempfile.TemporaryDirectory(prefix="qtest-replay-") as td:
            root = Path(td)
            rawpath = out / f"{mode}-{i}.raw"
            result, rc = qtest(root, operations, rawpath) if mode == "qtest" else guest(root, Path(bootpath), rawpath)
        require(not root.exists(), "temporary fixture cleanup")
        receipt = {"plan_sha256": hashlib.sha256(p).hexdigest(),
                   "vantage": mode, "observations": result, "process_exit": rc,
                   "cleanup": True, "elapsed_ns": time.monotonic_ns() - start}
        (out / f"{mode}-{i}.json").write_text(json.dumps(receipt, sort_keys=True)+"\n")
        print(json.dumps(receipt), flush=True)

if __name__ == "__main__":
    main()
