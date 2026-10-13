#!/usr/bin/env python3
"""Synthetic compiler/decompiler inversion probe. Private APKs never enter this job.

Measure optimizer-induced loss and semantic preservation using known-source fixtures.
A green process is not a recovered-original-source claim. The evaluator owns the oracle.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT=Path(os.environ.get("RUNNER_TEMP","/tmp"))/"aar-inversion"
ROOT.mkdir(parents=True,exist_ok=True)
RECEIPT=ROOT/"receipt.json"
JADX_SHA="545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"
R8_JAR_SHA="a26ee56252adcff6752c379ae255a0ad538ebec60189e078ec6855487107637d"
SAMPLES=("-3","0","1","2","7","13")
result={"schema":"aar-source-informed-inversion/v1","fixture":"AUTHORED_PUBLIC_ONLY",
        "tools":{"jadx_zip_sha256":JADX_SHA,"r8_jar_sha256":R8_JAR_SHA},
        "experiments":{},"overall":"NOT_RUN"}

def exec_(args,timeout=90):
    start=time.monotonic()
    p=subprocess.run([str(x) for x in args],capture_output=True,text=True,
                     check=False,timeout=timeout)
    return p,round(time.monotonic()-start,3)

def require(cond,label):
    if not cond: raise AssertionError(label)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def persist():
    RECEIPT.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")

def main():
    sdk=Path(os.environ.get("ANDROID_HOME","/usr/local/lib/android/sdk"))
    r8candidates=sorted((sdk/"build-tools").glob("*/lib/d8.jar"),reverse=True)
    d8candidates=sorted((sdk/"build-tools").glob("*/d8"),reverse=True)
    platform=sorted((sdk/"platforms").glob("android-*/android.jar"),reverse=True)
    jadx=ROOT/"jadx"/"bin"/"jadx"
    require(r8candidates and d8candidates and platform and jadx.is_file(),"required_build_tools_absent")
    r8jar=r8candidates[0]
    require(sha(r8jar)==R8_JAR_SHA,"sdk_r8_identity_drift")
    v,_=exec_([jadx,"--version"],25)
    require(v.returncode==0 and "1.5.6" in v.stdout+v.stderr,"jadx_version_mismatch")
    src=ROOT/"src";cls=ROOT/"original";src.mkdir(exist_ok=True);cls.mkdir(exist_ok=True)
    java=src/"Probe.java"
    java.write_text("""public final class Probe {
  public static void main(String[] args) {
    try {
      int x = Integer.parseInt(args[0]);
      System.out.print(Helper.evaluate(x) + ":" + Helper.kind(x));
    } catch (IllegalArgumentException failure) { System.out.print("ERR"); }
  }
}
class Helper {
  static int evaluate(int x) {
    if (x < 0) throw new IllegalArgumentException();
    int v=0;
    for (int i=0;i<x;i++) { v += ((i*3)^7)%11; }
    return v;
  }
  static String kind(int x) { return x % 2 == 0 ? "EVEN" : "ODD"; }
}
class Decoy {
  static int evaluate(int x) { return x + 1000; }
}
""",encoding="utf-8")
    c,_=exec_(["javac","-g:none","-d",cls,java],30)
    require(c.returncode==0,"javac_fixture_compilation_failed")
    expected={}
    for value in SAMPLES:
        p,_=exec_(["java","-cp",cls,"Probe",value],20)
        require(p.returncode==0,"java_reference_execution_failed")
        expected[value]=p.stdout
    require(expected["-3"]=="ERR","negative_exception_oracle_drift")
    require(expected["2"]!=str(1002),"decoy_oracle_not_discriminating")
    result["source_sha256"]=sha(java)
    result["oracle"]={"inputs":list(SAMPLES),"expected_outputs":expected,
                      "decoy_same_signature_different_behavior":True}
    rules=ROOT/"rules.pro"
    rules.write_text("-keep class Probe { public static void main(java.lang.String[]); }\n"
                     "-dontwarn **\n",encoding="utf-8")
    for mode in ("d8_only","r8_rename","r8_optimize"):
        d=ROOT/mode;d.mkdir(exist_ok=True)
        dexdir=d/"dex";dexdir.mkdir(exist_ok=True)
        out=d/"java_classes";out.mkdir(exist_ok=True)
        mapping=d/"mapping.txt"
        this_rules=d/"rules.pro"
        control=rules.read_text()
        if mode=="r8_rename": control+="-dontshrink\n-dontoptimize\n"
        this_rules.write_text(control)
        timing={}
        if mode=="d8_only":
            p,t=exec_([d8candidates[0],"--min-api","21","--output",dexdir,
                       *(str(x) for x in sorted(cls.glob("*.class")))],80)
            timing["dex_compile_s"]=t
            require(p.returncode==0,"d8_failed")
            # Baseline uses unmodified compiled Java.
            classes=cls
        else:
            basic=["java","-cp",r8jar,"com.android.tools.r8.R8",
                   "--pg-conf",this_rules,"--pg-map-output",mapping,
                   "--lib",platform[0]]
            input_classes=[str(x) for x in sorted(cls.glob("*.class"))]
            p,t=exec_([*basic,"--min-api","21","--output",dexdir,*input_classes],90)
            timing["dex_compile_s"]=t
            require(p.returncode==0,"r8_dex_failed_"+mode)
            p,t=exec_([*basic,"--classfile","--output",out,*input_classes],90)
            timing["classfile_compile_s"]=t
            require(p.returncode==0,"r8_classfile_failed_"+mode)
            classes=out
            require(mapping.exists(),"r8_mapping_missing")
        dex=dexdir/"classes.dex"
        require(dex.is_file(),"compiled_dex_absent_"+mode)
        outputs={}
        for value in SAMPLES:
            p,_=exec_(["java","-cp",classes,"Probe",value],20)
            require(p.returncode==0,"jvm_execution_failed_"+mode)
            outputs[value]=p.stdout
        semantic_parity=outputs==expected
        decoded=d/"jadx_output"
        p,t=exec_([jadx,"-d",decoded,dex],90)
        timing["jadx_s"]=t
        decompiled=[f for f in decoded.rglob("*.java")]
        decomptext="\n".join(f.read_text(errors="replace") for f in decompiled)
        main_seen="main(" in decomptext
        renamed=False
        helper_mapping="UNKNOWN"
        if mapping.exists():
            found=re.search(r"(?m)^Helper -> ([^:]+):$",mapping.read_text())
            helper_mapping=found.group(1) if found else "REMOVED_OR_MERGED"
            renamed=helper_mapping not in ("UNKNOWN","Helper","REMOVED_OR_MERGED")
        result["experiments"][mode]={
            "status":"PASS_ORACLE" if semantic_parity and main_seen and p.returncode==0 else "FAIL_ORACLE",
            "runtime_semantic_parity":semantic_parity,
            "java_main_decompiled":main_seen,
            "jadx_exit_code":p.returncode,
            "decompiled_java_files":len(decompiled),
            "original_helper_symbol_seen":"Helper" in decomptext,
            "helper_mapping":helper_mapping,
            "helper_renamed_by_compiler":renamed,
            "dex_sha256":sha(dex),
            "mapping_sha256":sha(mapping) if mapping.exists() else None,
            "timings":timing}
        persist()
    require(result["experiments"]["d8_only"]["status"]=="PASS_ORACLE","baseline_failed")
    require(result["experiments"]["r8_rename"]["status"]=="PASS_ORACLE","rename_failed")
    require(result["experiments"]["r8_optimize"]["status"]=="PASS_ORACLE","optimize_failed")
    require(result["experiments"]["r8_rename"]["helper_renamed_by_compiler"],
            "did_not_observe_compiler_renaming")
    result["overall"]="PASS_THREE_SYNTHETIC_ORACLE_TREATMENTS"
    persist()
    print(json.dumps({"overall":result["overall"],"modes":{
        m:{"status":v["status"],"semantic_parity":v["runtime_semantic_parity"],
           "mapping":v["helper_mapping"]} for m,v in result["experiments"].items()}},
        sort_keys=True))
    return 0

try:
    sys.exit(main())
except Exception as error:
    result["overall"]="FAIL_OR_BLOCKED"
    result["failure"]={"type":type(error).__name__,"reason":str(error)[:180]}
    persist()
    print(json.dumps({"overall":result["overall"],"failure":result["failure"]}))
    sys.exit(1)
