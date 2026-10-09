#!/usr/bin/env python3
"""Cheap exact-source qualification of upstream 9.5 dependency probes."""
import json
import os
import pathlib
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import winbot_95_dependency_probe_patch as p
import winbot_95_dependency_receipt_patch as r
import winbot_95_receipt_patch as receipt_parent
from winbot_95_static_qualification import get_exact_blob
def main():
    c=get_exact_blob(p.PARENT)
    w=receipt_parent.patch_receipt(get_exact_blob(receipt_parent.PARENT_WORKFLOW_BLOB))
    assert r.identity(w)==r.PARENT, 'derived receipt parent identity drift'
    new_c=p.patch(c)
    new_w=r.patch(w)
    assert new_c==p.patch(c) and new_w==r.patch(w), "nondeterministic"
    assert p.identity(new_c)!=p.PARENT
    assert r.identity(new_w)!=r.PARENT
    for func,data in ((p.patch,c+b" "), (r.patch,w+b" ")):
        try: func(data)
        except ValueError: pass
        else: raise AssertionError("wrong parent accepted")
    src_c=new_c.decode("utf-8")
    src_w=new_w.decode("utf-8")
    for key in p.SIGNALS:
        assert src_c.count(key)>=1 and src_w.count("'"+key+"'")>=1, key
    assert len(p.SIGNALS)==18
    for required in ("CriticalFailureMarkerState","CriticalFailureFlags",
                     "DependencyProbeState","DependencyProbe","deterministic_nat_absent",
                     "Remove-RunWorkCell","9.5/9-ready"):
        assert required in src_c
    assert "ConvertFrom-Json -AsHashtable -Depth 100" in src_w
    assert src_w.count("dependency_probe_state = $dependencyState")==1
    assert src_w.count("dependency_probe = $dependencyFlags")==1
    assert "dependency_probe = $r.work_cells.a.dependency_probe" not in src_w
    assert "agent-dispatch-heavyweight-rdte" in src_w
    for banned in ("Write-Host $sample","DependencyProbe = $sample",
                   "dependency_probe = $r.work_cells.a.dependency_probe",
                   "dependency_probe = $rawLog"):
        assert banned not in src_c and banned not in src_w, banned
    out=pathlib.Path(os.environ.get("RUNNER_TEMP","/tmp"))/"winbot-95-deps"
    out.mkdir(exist_ok=True,parents=True)
    (out/"candidate-control.ps1").write_bytes(new_c)
    (out/"candidate-wrapper.yml").write_bytes(new_w)
    receipt={
      "classification":"CHEAP_DEPENDENCY_PROBE_CANDIDATE_ONLY",
      "parent_control_blob":p.PARENT,"candidate_control_blob":p.identity(new_c),
      "parent_receipt_wrapper_blob":r.PARENT,"candidate_receipt_wrapper_blob":r.identity(new_w),
      "flags_count":len(p.SIGNALS),"product_source_unchanged":True,
      "projection_unchanged":True,"heavy_guest_launched":False}
    (out/"qualification.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__":main()
