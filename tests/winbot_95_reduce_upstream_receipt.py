#!/usr/bin/env python3
"""Synthetic falsification of bounded WinBot upstream evidence reducer."""
import copy
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"scripts"))
import winbot_95_reduce_upstream_receipt as m

def base():
    return {
        "source_revision": m.SOURCE,
        "projection_identity_sha256": m.PROJECTION,
        "classification": "ORACLE_FAILURE",
        "a": {
            "provision_status": "failed",
            "critical_failure_marker_state": "valid",
            "critical_failure_flags": {x: x=="api_present" for x in m.CRITICAL},
            "dependency_probe_state": "valid",
            "dependency_probe": {x: False for x in m.DEPENDENCY},
        },
        "cleanup": {**{x: True for x in m.CLEANUP}, "netnat_count_after_cleanup":0},
    }

def run():
    a=base()
    r=m.reduce_bounded(a)
    assert r["evidence_acceptance"]=="valid"
    assert r["failure_class"]=="runtime_dependency_absence"
    assert r["seed_admission"]=="BLOCKED" and r["terminal_admission"]=="BLOCKED"
    assert r["critical_false_keys"]==[x for x in m.CRITICAL if x!="api_present"]
    assert r["cleanup_complete"] is True
    for flag in m.DEPENDENCY:
        v=base()
        v["a"]["dependency_probe"][flag]=True
        rr=m.reduce_bounded(v)
        assert rr["evidence_acceptance"]=="valid" and "observed_"+flag in rr["positive_signals"]
    v=base(); v["a"]["dependency_probe"].pop(m.DEPENDENCY[0])
    assert m.reduce_bounded(v)["dependency_flags_valid"] is False
    v=base(); v["a"]["dependency_probe"][m.DEPENDENCY[0]]="false"
    assert m.reduce_bounded(v)["dependency_flags_valid"] is False
    v=base(); v["a"]["dependency_probe"][m.DEPENDENCY[0]]=None
    assert m.reduce_bounded(v)["dependency_flags_valid"] is False
    v=base(); v["a"]["dependency_probe"]["EXTRA"]="untrusted"
    assert m.reduce_bounded(v)["dependency_flags_valid"] is False
    v=base(); v["a"]["critical_failure_flags"][m.CRITICAL[0]]="true"
    assert m.reduce_bounded(v)["critical_flags_valid"] is False
    v=base(); v["a"]["critical_failure_marker_state"]="unreadable"
    assert m.reduce_bounded(v)["evidence_acceptance"]=="incomplete"
    v=base(); v["a"]["critical_failure_flags"]={x:True for x in m.CRITICAL}
    assert m.reduce_bounded(v)["failure_class"]=="product_ready_conflicting_terminal"
    v=base(); v["cleanup"]["vm_a_absent"]=False
    assert m.reduce_bounded(v)["failure_class"]=="cleanup_not_proved"
    assert m.reduce_bounded(v)["seed_admission"]=="BLOCKED"
    v=base(); v["cleanup"]["netnat_count_after_cleanup"]=1
    assert m.reduce_bounded(v)["cleanup_complete"] is False
    v=base(); v["source_revision"]="invalid"
    try: m.reduce_bounded(v)
    except ValueError: pass
    else: raise AssertionError("untrusted identity accepted")
    v=base(); v["a"]["unexpected"]={"private":"UNTRUSTED"}
    out=json.dumps(m.reduce_bounded(v),sort_keys=True)
    assert "UNTRUSTED" not in out and '"private"' not in out
    print("WINBOT_95_UPSTREAM_BOUNDED_REDUCER_PASS")
if __name__=="__main__":
    run()
