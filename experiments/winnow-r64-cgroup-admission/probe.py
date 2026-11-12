#!/usr/bin/env python3
"""R64 strict public-native cgroup v2 admission probe, not a product sandbox."""
import errno
import json
import os
from pathlib import Path
import sys

NEEDED={"cpu","memory","pids"}
LIMITS={"cpu.max":"50000 100000","memory.max":str(64<<20),"pids.max":"8"}

def blocked(reason,detail=""):
    data={"scope":"PUBLIC_SYNTHETIC_CGROUP_V2_PROVISIONING_ONLY",
          "arch":os.uname().machine,"decision":"BLOCKED",
          "reason":reason,"detail":detail[:160],
          "private_source":False,"real_extractor":False,
          "enforcement_tested":False,"product_qualified":False}
    print(json.dumps(data,sort_keys=True),flush=True)
    print("R64_CGROUP_V2_ADMISSION_BLOCKED reason="+reason,flush=True)
    sys.exit(2)

def main():
    if os.geteuid()!=0:blocked("NOT_ROOT_IN_DISPOSABLE_RUNNER")
    cg=Path("/sys/fs/cgroup")
    try:
        controllers=(cg/"cgroup.controllers").read_text().split()
    except OSError as e:
        blocked("CGROUP_V2_NOT_MOUNTED",str(e))
    if not NEEDED.issubset(controllers):
        blocked("MISSING_REQUIRED_CONTROLLERS",",".join(sorted(set(NEEDED)-set(controllers))))
    try:
        active=set((cg/"cgroup.subtree_control").read_text().split())
    except OSError as e:
        blocked("SUBTREE_CONTROL_UNREADABLE",str(e))
    if not NEEDED.issubset(active):
        blocked("UNDELEGATED_CONTROLLER_SET",",".join(sorted(NEEDED-active)))
    name="winnow-r64-"+str(os.getpid())
    trial=cg/name
    try:
        try:
            trial.mkdir(mode=0o700)
        except OSError as e:
            blocked("NO_WRITABLE_CHILD_CGROUP",f"errno={e.errno}")
        observed={}
        for filename,value in LIMITS.items():
            try:
                (trial/filename).write_text(value)
                got=(trial/filename).read_text().strip()
            except OSError as e:
                blocked("CGROUP_CONTROLLER_WRITE_DENIED",f"{filename} errno={e.errno}")
            if got!=value:
                blocked("CGROUP_CONFIG_MISMATCH",f"{filename} requested={value} got={got}")
            observed[filename]=got
        print(json.dumps({"scope":"PUBLIC_SYNTHETIC_CGROUP_V2_PROVISIONING_ONLY",
                          "arch":os.uname().machine,"decision":"PROVISIONED",
                          "controllers":sorted(NEEDED),"configured":observed,
                          "enforcement_tested":False,"private_source":False,
                          "real_extractor":False,"product_qualified":False,
                          "host":"DISPOSABLE_GITHUB_RUNNER_ONLY"},sort_keys=True),flush=True)
        print("R64_CGROUP_V2_PROVISIONING_ADMITTED arch=%s enforcement=NOT_RUN product=HOLD"%os.uname().machine,flush=True)
    finally:
        if trial.exists():
            try:trial.rmdir()
            except OSError as e:
                print("R64_CGROUP_TEARDOWN_FAILED errno=%s"%e.errno,flush=True)
                raise

if __name__=="__main__":main()
