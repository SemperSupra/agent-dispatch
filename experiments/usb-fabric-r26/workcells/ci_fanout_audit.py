#!/usr/bin/env python3
"""Offline conservative inventory of USB Fabric workflow pull_request trigger breadth.

No YAML dependency. This only classifies explicit top-level event blocks and
does not change workflow behavior or estimate billable minutes.
"""
import json
from pathlib import Path
import re
import sys

def classify(source):
    lines=source.splitlines()
    in_pull=False
    in_on=False
    has_pr=False
    paths=False
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ","\t")):
            in_pull=False
            in_on=False
            if re.match(r"^on:\s*(\{.*|\[.*)$",line):
                # Inline YAML not parsed; force unknown rather than false safety.
                return "UNKNOWN_INLINE_TRIGGER"
            if line.strip()=="on:":
                in_on=True
            continue
        if in_on and re.match(r"^  pull_request:\s*(?:\{|\[|$)",line):
            has_pr=True
            in_pull=True
            if "paths:" in line or "paths-ignore:" in line:
                paths=True
            continue
        if in_on and re.match(r"^  [A-Za-z_][\w-]*:",line):
            in_pull=False
        if in_pull and re.match(r"^    paths(?:-ignore)?:",line):
            paths=True
    if not has_pr:
        return "NO_EXPLICIT_PR_TRIGGER"
    return "SCOPED_PR_PATHS" if paths else "BROAD_PR_TRIGGER"

def self_test():
    examples={
        "on:\n  pull_request:\n    types: [opened]\n":"BROAD_PR_TRIGGER",
        "on:\n  pull_request:\n    paths:\n      - foo/**\n":"SCOPED_PR_PATHS",
        "on:\n  push:\n    branches: [main]\n":"NO_EXPLICIT_PR_TRIGGER",
        "name: test\non: [push, pull_request]\n":"UNKNOWN_INLINE_TRIGGER",
    }
    for s,expected in examples.items():
        actual=classify(s)
        assert actual==expected,(expected,actual)
    print("USB_FABRIC_CI_FANOUT_CLASSIFIER_SELF_TEST=PASS",flush=True)

def main():
    self_test()
    root=Path(".github/workflows")
    if not root.is_dir(): raise SystemExit("workflow root absent")
    rows=[]
    for p in sorted(root.glob("*.y*ml")):
        contents=p.read_text(errors="replace")
        name=""
        for line in contents.splitlines():
            if line.startswith("name:"):
                name=line[5:].strip().strip("'\"")
                break
        if "USB Fabric" not in name and "usbfabric" not in p.name.lower():
            continue
        rows.append({"file":str(p),"name":name,"pr_trigger":classify(contents)})
    if not rows: raise SystemExit("no USB Fabric workflows found")
    counts={k:sum(x["pr_trigger"]==k for x in rows) for k in
      ("BROAD_PR_TRIGGER","SCOPED_PR_PATHS","NO_EXPLICIT_PR_TRIGGER","UNKNOWN_INLINE_TRIGGER")}
    print("USB_FABRIC_CI_WORKFLOW_TRIGGER_INVENTORY="+json.dumps(
        {"total":len(rows),"counts":counts,"workflows":rows},sort_keys=True),flush=True)
    print("USB_FABRIC_CI_TRIGGER_AUDIT=PASS",flush=True)
    print("USB_FABRIC_CI_BILLED_MINUTES=NOT_TESTED",flush=True)
    print("USB_FABRIC_CI_RELEASE_GATE_RESTRUCTURE=NOT_TESTED",flush=True)
if __name__=="__main__":main()
