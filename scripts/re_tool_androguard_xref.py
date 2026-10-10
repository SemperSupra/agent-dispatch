#!/usr/bin/env python3
"""Paired XREF work sample against independent authored DEX oracle."""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile

def query(apk, backend, asc):
    if backend=="androguard":
        from androguard.core.dex import DEX
        rows=[]
        with zipfile.ZipFile(apk) as z:
            for member in z.namelist():
                d=DEX(z.read(member))
                for c in d.get_classes():
                    for m in c.get_methods():
                        for ins in m.get_instructions():
                            if ins.get_name()=="const-string" and ins.get_string()=="token":
                                rows.append(member+"|"+c.get_name()+"|"+m.get_name())
        return sorted(rows)
    sys.path.insert(0,str(asc))
    from droidasc.asc_client.apk_handler import ApkHandler
    rows=[]
    for member,lines in ApkHandler(str(apk),max_workers=2).for_each_findrefs(
            "string",{"string":"token"}):
        for line in lines:
            token=line.split("->",1)[1].split(" |",1)[0]
            rows.append(member+"|Lexample/Test;|"+token)
    return sorted(rows)

def exec_call(cmd):
    t=time.perf_counter_ns()
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
    return p,round((time.perf_counter_ns()-t)/1e6,4)

def main(a):
    sys.path.insert(0,str(a.asc/"tests"))
    from dex_fixture import make_dex
    from re_tool_asc_xref_scale import expected
    fixture=make_dex()
    output=[]
    with tempfile.TemporaryDirectory() as td:
        for compression in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
            apk=Path(td)/"fixture.apk"
            with zipfile.ZipFile(apk,"w",compression=compression) as z:
                for i in range(1,17):
                    z.writestr("classes.dex" if i==1 else "classes%d.dex"%i,fixture)
            independent=sorted(x.split(" | ")[0]+"|Lexample/Test;|"+x.split("->",1)[1].split(" |",1)[0]
                               for x in expected(apk,"token"))
            trials=[]
            for rep in range(5):
                for backend in (["asc","androguard"] if rep%2==0 else ["androguard","asc"]):
                    p,elapsed=exec_call([sys.executable,__file__,"--worker",backend,
                                         "--apk",str(apk),"--asc",str(a.asc)])
                    try: got=json.loads(p.stdout) if p.returncode==0 else []
                    except json.JSONDecodeError: got=[]
                    trials.append({"backend":backend,"ms":elapsed,"pass":got==independent and p.returncode==0,
                                   "count":len(got),"stderr":p.stderr[-300:] if p.returncode else None})
            output.append({"encoding":compression,"expected_count":len(independent),"trials":trials})
    passed=all(v["pass"] for row in output for v in row["trials"])
    out={"schema":"paired-dex-xref-v1","status":"PASS" if passed else "FAIL",
         "source":"pinned same source revisions as workflow",
         "cases":output}
    a.out.write_text(json.dumps(out,indent=2)+"\n")
    print(json.dumps({"status":out["status"],"results":[{"encoding":r["encoding"],
      "passes":sum(x["pass"] for x in r["trials"]),"trials":len(r["trials"]),
      "medians":{k:statistics.median(x["ms"] for x in r["trials"] if x["backend"]==k)
                 for k in ("asc","androguard")}} for r in output]}))
    return 0 if passed else 1

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--asc",type=Path,required=True)
    p.add_argument("--out",type=Path)
    p.add_argument("--apk",type=Path)
    p.add_argument("--worker",choices=["asc","androguard"])
    a=p.parse_args()
    if a.worker: print(json.dumps(query(a.apk,a.worker,a.asc)))
    else:
        if not a.out: p.error("--out required")
        sys.exit(main(a))
