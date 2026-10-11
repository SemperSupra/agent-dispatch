#!/usr/bin/env python3
"""Optional evidence-only Droid ASC provider projection; not an AAR control plane.

No installation, network, mutation of an APK, or private corpus on public runners.
Upstream git commit and input archive SHA must be known before invoking the CLI.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

PIN = "464f9fef0db41099c4cf3f55c78b33f2606780d2"
SCHEMA = "aar-optional-droidasc-discovery/v0"
MAX_INPUT = 128 * 1024 * 1024
MAX_DEX = 64
MAX_LINES = 300000

def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536),b""):
            h.update(chunk)
    return h.hexdigest()

def validate_query(query):
    if query is None: return None
    if not isinstance(query,str) or not query.strip() or len(query)>128:
        raise ValueError("invalid_query_length")
    if any(ord(x)<32 or ord(x)==127 for x in query):
        raise ValueError("control_character_in_query")
    return query

def inspect_input(path, expected_sha):
    if not path.is_file() or path.is_symlink(): raise ValueError("input_missing_or_symlink")
    if path.stat().st_size>MAX_INPUT: raise ValueError("input_too_large")
    if digest(path)!=expected_sha.lower(): raise ValueError("input_hash_mismatch")
    with zipfile.ZipFile(path) as archive:
        dex=[n for n in archive.infolist() if
             n.filename=="classes.dex" or
             (re.fullmatch(r"classes[0-9]+\.dex",n.filename) is not None)]
        if not dex or len(dex)>MAX_DEX: raise ValueError("dex_members_outside_bounds")
        if len({x.filename for x in dex})!=len(dex):
            raise ValueError("duplicate_dex_members")
        if any(x.file_size>MAX_INPUT for x in dex) or sum(x.file_size for x in dex)>MAX_INPUT:
            raise ValueError("dex_uncompressed_bytes_exceed_bound")
        if any(x.flag_bits & 1 for x in dex): raise ValueError("encrypted_dex_member")
        return [{"member":x.filename,"uncompressed_size":x.file_size} for x in dex]

def source_pin(checkout):
    p=subprocess.run(["git","-C",str(checkout),"rev-parse","HEAD"],
                     capture_output=True,text=True,timeout=15)
    if p.returncode or p.stdout.strip()!=PIN: raise ValueError("upstream_source_revision_mismatch")
    cli=checkout/"main.py"
    if not cli.is_file(): raise ValueError("upstream_cli_not_materialized")
    reference=subprocess.run(["git","-C",str(checkout),"show","HEAD:main.py"],
                             capture_output=True,timeout=15)
    if reference.returncode or cli.read_bytes()!=reference.stdout:
        raise ValueError("upstream_cli_content_mismatch")
    return cli

def get_lines(argv):
    proc=subprocess.run(argv,capture_output=True,text=True,timeout=70)
    if proc.returncode: raise RuntimeError("upstream_cli_nonzero_exit")
    lines=proc.stdout.splitlines()
    if len(lines)>MAX_LINES: raise ValueError("result_line_count_exceeds_bound")
    return lines

def discover(checkout, apk, declared_hash, prefix=None, string_query=None):
    prefix=validate_query(prefix)
    string_query=validate_query(string_query)
    if prefix is None and string_query is None: raise ValueError("no_observation_requested")
    cli=source_pin(checkout)
    members=inspect_input(apk,declared_hash)
    base=[sys.executable,"-S",str(cli)]
    results={}
    if prefix is not None:
        results["classes"]=get_lines(base+["listclass",str(apk),"--threads","2","--prefix",prefix])
    if string_query is not None:
        results["string_reference_lines"]=get_lines(
            base+["findrefs",str(apk),"--threads","2","string",string_query])
    return {"schema":SCHEMA,"qualification":"OPTIONAL_DISCOVERY_ONLY",
            "source":{"repository":"MG1937/ASC","revision":PIN},
            "input":{"archive_sha256":declared_hash.lower(),"dex_members":members},
            "parameters":{"prefix":prefix,"string_query":string_query,
                          "query_matching":"UPSTREAM_FUZZY_STRING_MATCH"},
            "results":results,
            "proof_boundaries":["No code execution equivalence",
                                "No evaluator oracle was ingested",
                                "No automatic production promotion"]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream",type=Path,required=True)
    p.add_argument("--apk",type=Path,required=True)
    p.add_argument("--sha256",required=True)
    p.add_argument("--prefix")
    p.add_argument("--string-query")
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if not re.fullmatch(r"[0-9a-fA-F]{64}",a.sha256):p.error("bad SHA256 format")
    if a.apk.resolve()==a.out.resolve():p.error("output must not equal input")
    payload=discover(a.upstream,a.apk,a.sha256,a.prefix,a.string_query)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    # Publish a complete result atomically; errors never emit a partial success.
    with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=a.out.parent,
                                     prefix=".aar-discovery-",suffix=".tmp",
                                     delete=False) as fh:
        scratch=Path(fh.name)
        json.dump(payload,fh,sort_keys=True,indent=2)
        fh.write("\n")
    try: scratch.replace(a.out)
    finally: scratch.unlink(missing_ok=True)
    print(json.dumps({"status":"PASS_SCOPED_DISCOVERY",
                      "classes":len(payload["results"].get("classes",[])),
                      "string_reference_lines":len(payload["results"].get("string_reference_lines",[])),
                      "output_sha256":digest(a.out)},sort_keys=True))

if __name__=="__main__":
    try:main()
    except (OSError,ValueError,RuntimeError,zipfile.BadZipFile,subprocess.TimeoutExpired) as ex:
        print("DISCOVERY_HOLD:"+type(ex).__name__+":"+str(ex),file=sys.stderr)
        sys.exit(2)
