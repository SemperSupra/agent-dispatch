#!/usr/bin/env python3
"""External synthetic-only acceptance check for staged AAR Droid ASC adapter."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

def main(root, output):
    sys.path.insert(0,str(root/"tests"))
    from dex_fixture import make_dex
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    adapter=Path(__file__).with_name("re_tool_optional_discovery.py")
    receipt={"schema":"aar-optional-discovery-interview/v0","positive":[],
             "negative":[],"status":"INCOMPLETE"}
    with tempfile.TemporaryDirectory() as t:
        work=Path(t)
        apk=work/"synthetic.apk"
        with zipfile.ZipFile(apk,"w",compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("classes.dex",make_dex())
            z.writestr("classes2.dex",make_dex())
        original=sha(apk)
        dest=work/"receipt.json"
        base=[sys.executable,"-S",str(adapter),"--upstream",str(root),
              "--apk",str(apk),"--sha256",original,"--out",str(dest)]
        def invoke(args):
            return subprocess.run(args,text=True,capture_output=True,timeout=90)
        p=invoke(base+["--prefix","example","--string-query","token"])
        if p.returncode:
            raise RuntimeError("positive_workload_failed:"+p.stderr[-400:])
        observed=json.loads(dest.read_text())
        expected_classes=["Lexample/Test;","Lexample/Test;"]
        checks=[
            observed["source"]["revision"]=="464f9fef0db41099c4cf3f55c78b33f2606780d2",
            observed["input"]["archive_sha256"]==original,
            observed["results"]["classes"]==expected_classes,
            len(observed["results"]["string_reference_lines"])==4,
            sha(apk)==original
        ]
        receipt["positive"]=[{"id":str(i),"pass":v} for i,v in enumerate(checks)]
        dest.unlink()
        corrupted="0"*64
        controls=[
            ("wrong_sha",base[:base.index("--sha256")+1]+[corrupted]+base[base.index("--sha256")+2:]+["--prefix","example"]),
            ("missing_query",base),
            ("invalid_query",base+["--prefix","\n"]),
            ("invalid_upstream",base[:base.index("--upstream")+1]+[str(work)]+base[base.index("--upstream")+2:]+["--prefix","example"]),
        ]
        for name,args in controls:
            p=invoke(args)
            receipt["negative"].append({"id":name,"rejected":p.returncode!=0 and not dest.exists()})
        # A fake, oversize member count must fail before the upstream is run.
        flood=work/"flood.apk"
        with zipfile.ZipFile(flood,"w") as z:
            for k in range(1,67):
                z.writestr("classes.dex" if k==1 else f"classes{k}.dex",make_dex())
        flood_args=base[:]
        flood_args[flood_args.index("--apk")+1]=str(flood)
        flood_args[flood_args.index("--sha256")+1]=sha(flood)
        p=invoke(flood_args+["--prefix","example"])
        receipt["negative"].append({"id":"too_many_dex","rejected":p.returncode!=0 and not dest.exists()})
    receipt["status"]="PASS" if all(i["pass"] for i in receipt["positive"]) and all(i["rejected"] for i in receipt["negative"]) else "FAIL"
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print("OPTIONAL_DISCOVERY_INTERVIEW",json.dumps(receipt,sort_keys=True))
    return 0 if receipt["status"]=="PASS" else 1

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: test UPSTREAM_CHECKOUT OUT.json")
    sys.exit(main(Path(sys.argv[1]),Path(sys.argv[2])))
