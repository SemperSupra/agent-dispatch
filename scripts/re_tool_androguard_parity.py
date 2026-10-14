#!/usr/bin/env python3
"""Public synthetic Android DEX enumeration; pinned source A/B trial."""
import argparse
import hashlib
import json
import resource
from pathlib import Path
import statistics
import subprocess
import struct
import zlib
import sys
import tempfile
import time
import zipfile

ASC = "464f9fef0db41099c4cf3f55c78b33f2606780d2"
AG = "d594fd39beb934e438a5bf8089b206d5800d81e0"

def canonical_checksum(data):
    b=bytearray(data)
    b[12:32]=hashlib.sha1(b[32:]).digest()
    struct.pack_into("<I",b,8,zlib.adler32(b[12:]) & 0xffffffff)
    assert struct.unpack_from("<I",b,8)[0]==(zlib.adler32(b[12:]) & 0xffffffff)
    return bytes(b)

def run(cmd):
    t = time.perf_counter_ns()
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return p, round((time.perf_counter_ns()-t)/1e6, 5)

def andro_classes(archive):
    from androguard.core.dex import DEX
    with zipfile.ZipFile(archive) as z:
        return [c.get_name() for name in ("classes.dex", "classes2.dex")
                for c in DEX(z.read(name)).get_classes()]

def main(args):
    for where,pin in ((args.asc,ASC),(args.and_source,AG)):
        p,_ = run(["git","-C",str(where),"rev-parse","HEAD"])
        assert p.returncode==0 and p.stdout.strip()==pin, "source pin mismatch"
    sys.path.insert(0,str(args.asc/"tests"))
    from test_listclass import make_class_only_dex
    from re_tool_asc_multidex import header_names
    left=["Lrequal/Left%05d;"%i for i in range(1200)]
    right=["Lrequal/Right%05d;"%i for i in range(1200)]+left[:64]
    a,b=(canonical_checksum(make_class_only_dex(left)),
         canonical_checksum(make_class_only_dex(right)))
    assert header_names(a)==left and header_names(b)==right
    receipts=[]
    with tempfile.TemporaryDirectory() as td:
        for compression in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
            apk=Path(td)/("fixture-%d.apk"%compression)
            with zipfile.ZipFile(apk,"w",compression=compression) as z:
                z.writestr("classes.dex",a)
                z.writestr("classes2.dex",b)
            expected=left+right
            timing={"asc":[],"androguard":[]}
            cases=[]
            for trial in range(6):
                backends=["asc","androguard"] if trial%2==0 else ["androguard","asc"]
                for name in backends:
                    p,ms=run([sys.executable,__file__,"--worker",name,
                              "--apk",str(apk),"--asc",str(args.asc)])
                    try: worker=json.loads(p.stdout) if p.returncode==0 else {}
                    except json.JSONDecodeError: worker={}
                    observed=worker.get("classes",[])
                    rss_kib=worker.get("rss_kib")
                    cases.append({"backend":name,"trial":trial,"ok":p.returncode==0 and observed==expected,
                                  "count":len(observed),"rss_kib":rss_kib,"error":p.stderr[-300:] if p.returncode else None})
                    timing[name].append(ms)
            receipts.append({"compression":compression,"expected":len(expected),"cases":cases,
                             "median_ms":{k:statistics.median(v) for k,v in timing.items()},
                             "median_rss_kib":{k:statistics.median(row["rss_kib"] for row in cases if row["backend"]==k and row["rss_kib"] is not None) for k in timing}})
    verdict=all(row["ok"] for r in receipts for row in r["cases"])
    payload={"schema":"asc-androguard-4.1.4-class-parity/v1","status":"PASS" if verdict else "FAIL",
             "asc_git":ASC,"androguard_git":AG,"generated_sha256":[hashlib.sha256(x).hexdigest() for x in (a,b)],
             "scope":"synthetic class definitions only","results":receipts}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(payload,indent=2)+"\n")
    print(json.dumps({"status":payload["status"],"cases":sum(len(r["cases"]) for r in receipts),
                      "results":[{"compression":r["compression"],"median_ms":r["median_ms"],"median_rss_kib":r["median_rss_kib"],
                                  "matches":sum(x["ok"] for x in r["cases"])} for r in receipts]}))
    return 0 if verdict else 1

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--asc",type=Path,required=True)
    p.add_argument("--and-source",type=Path)
    p.add_argument("--out",type=Path)
    p.add_argument("--worker",choices=["asc","androguard"])
    p.add_argument("--apk",type=Path)
    a=p.parse_args()
    if a.worker:
        if a.worker=="androguard":
            names=andro_classes(a.apk)
        else:
            sys.path.insert(0,str(a.asc))
            from droidasc.asc_client.apk_handler import ApkHandler
            names=ApkHandler(str(a.apk),max_workers=2).list_classes(None)
        print(json.dumps({"classes":names,"rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
    else:
        if not a.and_source or not a.out: p.error("missing --and-source or --out")
        sys.exit(main(a))
