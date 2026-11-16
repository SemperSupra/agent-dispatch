#!/usr/bin/env python3
"""Create fixed-time newc initramfs with /init and char /dev/console.
Build-only stdlib fixture: no mknod privileges and no host mounts needed."""
import gzip
import io
import os
import stat
import sys

def pad4(out):
    out.write(b"\0" * ((-out.tell()) % 4))

def add(out, ino, name, mode, data=b"", rdev=(0, 0)):
    n = name.encode("ascii") + b"\0"
    fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, rdev[0], rdev[1], len(n), 0)
    out.write(("070701" + "".join("%08x" % f for f in fields)).encode("ascii"))
    out.write(n)
    pad4(out)
    out.write(data)
    pad4(out)

def main():
    if len(sys.argv)!=3: raise SystemExit("mkinitrd.py ELF OUT.gz")
    data=open(sys.argv[1], "rb").read()
    if not data.startswith(b"\x7fELF"): raise SystemExit("not ELF")
    out=io.BytesIO()
    add(out, 1, "dev", stat.S_IFDIR|0o755)
    add(out, 2, "dev/console", stat.S_IFCHR|0o600, rdev=(5,1))
    add(out, 3, "dev/null", stat.S_IFCHR|0o666, rdev=(1,3))
    add(out, 4, "init", stat.S_IFREG|0o755, data)
    add(out, 5, "TRAILER!!!", 0)
    with open(sys.argv[2], "wb") as fp:
        with gzip.GzipFile(filename="", mode="wb", fileobj=fp, mtime=0, compresslevel=9) as gz:
            gz.write(out.getvalue())
    print("R04_SYNTHETIC_NEW_CPIO_INITRAMFS=BUILT",os.path.getsize(sys.argv[2]))
if __name__=="__main__": main()
