#!/usr/bin/env python3
"""Portable representative Agent Dispatch workload used by local/GHA parity T4."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import platform
import shutil
import subprocess
import sys
import time

SCHEMA = "semper-supra.runner-runtime-agent-contract/v1"
IMAGE = "python:3.13-alpine"


def run(cmd: list[str], cwd: pathlib.Path, timeout: int = 180) -> tuple[int, str, str]:
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)
    return p.returncode, p.stdout, p.stderr


def qualify(repo: pathlib.Path, mode: str) -> dict:
    start=time.monotonic()
    command=[sys.executable,"-m","unittest","-v","tests/test_sealed_public_execution.py"]
    container_digest=None
    if mode=="native":
        rc,out,err=run(command,repo)
    elif mode=="docker":
        docker=shutil.which("docker")
        if not docker:
            rc,out,err=127,"","docker CLI unavailable"
        else:
            prc,pout,perr=run([docker,"pull","--quiet",IMAGE],repo,timeout=240)
            if prc!=0:
                rc,out,err=125,pout,perr
            else:
                irc,iout,ierr=run([docker,"image","inspect","--format","{{join .RepoDigests \",\"}}",IMAGE],repo)
                container_digest=iout.strip() if irc==0 else None
                dcmd=[
                    docker,"run","--rm","--network","none","--read-only",
                    "--tmpfs","/tmp:rw,nosuid,nodev,size=64m",
                    "--mount",f"type=bind,src={repo},dst=/src,readonly",
                    "-w","/src",IMAGE,
                    "python","-m","unittest","-v","tests/test_sealed_public_execution.py"
                ]
                rc,out,err=run(dcmd,repo,timeout=240)
                subprocess.run([docker,"image","rm","--force",IMAGE],cwd=repo,capture_output=True,check=False)
                if ierr and not err:
                    err=ierr
    else:
        raise ValueError(f"unsupported mode: {mode}")
    elapsed=round(time.monotonic()-start,3)
    passed=rc==0
    return {
        "schema":SCHEMA,
        "classification":"SUPPORTED" if passed else "ORACLE_FAILURE",
        "oracleSatisfied":passed,
        "workload":{
            "id":"agent-dispatch-sealed-public-execution-contract",
            "mode":mode,
            "source":"tests/test_sealed_public_execution.py",
            "network_during_workload":False,
            "repository_mount_read_only":mode=="docker",
            "container_root_read_only":mode=="docker",
        },
        "runner":{"system":platform.system(),"machine":platform.machine()},
        "container":{"image":IMAGE if mode=="docker" else None,"digest":container_digest},
        "result":{"exit_code":rc,"elapsed_seconds":elapsed},
        "stdout_sha256":hashlib.sha256(out.encode()).hexdigest(),
        "stderr_tail":err[-1600:] if err else None,
        "claim_boundary":"This receipt proves only the named representative workload in the selected mode; it does not imply full template parity, lifecycle, GARM execution, enhancement, or placement admission."
    }


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=["native","docker"],required=True)
    p.add_argument("--repo",type=pathlib.Path,default=pathlib.Path("."))
    p.add_argument("--out",type=pathlib.Path,required=True)
    a=p.parse_args()
    repo=a.repo.resolve()
    receipt=qualify(repo,a.mode)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"RUNNER_TEMPLATE_AGENT_CONTRACT_RECEIPT={a.out}")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["oracleSatisfied"] else 2


if __name__=="__main__":
    raise SystemExit(main())
