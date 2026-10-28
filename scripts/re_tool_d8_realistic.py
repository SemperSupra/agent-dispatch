#!/usr/bin/env python3
"""Source-authored Java -> pinned local D8 -> shared Android DEX evidence."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

SOURCE = """public final class Requal {
 public static String first(){return "token";}
 public static String second(){return "token";}
 public static String other(){return "unrelated";}
 public static String select(boolean b){return b ? first() : second();}
 public static void main(String[] a){System.out.print(first()+"-"+second());}
}
"""

def execute(cmd):
    p=subprocess.run([str(x) for x in cmd],capture_output=True,text=True,timeout=75)
    if p.returncode: raise RuntimeError("command failed: "+str(cmd[0])+" "+p.stderr[-400:])
    return p.stdout.strip() or p.stderr.strip()

def main(out):
    sdk=Path(os.environ.get("ANDROID_HOME","/usr/local/lib/android/sdk"))
    d8=sdk/"build-tools"/"35.0.0"/"d8"
    jar=d8.parent/"lib"/"d8.jar"
    if not d8.is_file() or not jar.is_file(): raise RuntimeError("exact installed D8 launcher/JAR not found")
    with tempfile.TemporaryDirectory() as base:
        base=Path(base)
        src=base/"Requal.java"
        src.write_text(SOURCE)
        classes=base/"classes"; classes.mkdir()
        execute(["javac","--release","17","-d",classes,src])
        runtime=execute(["java","-cp",classes,"Requal"])
        if runtime!="token-token": raise AssertionError("compiled Java runtime witness mismatch")
        dexdir=base/"dex"; dexdir.mkdir()
        execute([d8,"--min-api","26","--output",dexdir,classes/"Requal.class"])
        dex=(dexdir/"classes.dex").read_bytes()
        apk=base/"synthetic.apk"
        with zipfile.ZipFile(apk,"w",zipfile.ZIP_DEFLATED) as z: z.writestr("classes.dex",dex)
        from androguard.core.dex import DEX
        ag=DEX(dex)
        first=[c for c in ag.get_classes() if c.get_name()=="LRequal;"]
        assert len(first)==1
        from droidasc.asc_client.apk_handler import ApkHandler
        refs=[]
        for member,lines in ApkHandler(str(apk),max_workers=2).for_each_findrefs("string",{"string":"token"}):
            refs.extend(line.split("->",1)[1].split(" |",1)[0] for line in lines if "->" in line)
        truth=sorted(["first","second"])
        independent=[]
        for method in first[0].get_methods():
            for ins in method.get_instructions():
                if ins.get_name()=="const-string" and ins.get_string()=="token":
                    independent.append(method.get_name())
        result={
          "schema":"requal-d8-real-class-xref/v1",
          "d8_version":execute([d8,"--version"]),
          "d8_jar_sha256":hashlib.sha256(jar.read_bytes()).hexdigest(),
          "d8_launcher_sha256":hashlib.sha256(d8.read_bytes()).hexdigest(),
          "javac_version":execute(["javac","-version"]),
          "java_witness":runtime,
          "java_source_sha256":hashlib.sha256(SOURCE.encode()).hexdigest(),
          "dex_sha256":hashlib.sha256(dex).hexdigest(),
          "expected_methods":truth,
          "asc_methods":sorted(refs),
          "androguard_methods":sorted(independent),
          "pass":sorted(refs)==truth==sorted(independent),
          "scope":"source-authored D8 Android DEX, no APK from user or live service"
        }
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print("D8_REAL_WORLD_SYNTHETIC",json.dumps(result,sort_keys=True))
    return 0 if result["pass"] else 1

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: script OUT.json")
    raise SystemExit(main(Path(sys.argv[1])))
