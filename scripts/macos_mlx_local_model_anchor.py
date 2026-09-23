#!/usr/bin/env python3
"""Public-safe MLX local-model GPU runtime anchor for Mac transfer."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile

MLX_LM_VERSION="0.31.3"
MODEL_REPO="mlx-community/SmolLM-135M-Instruct-4bit"
MODEL_REVISION="642e06a"
PROMPT="Reply with exactly the single word ORBIT."
SEED=1729
MAX_TOKENS=12
SCHEMA="macos-mlx-local-model-anchor/v1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def run(argv:list[str], timeout:int=600):
    try:
        cp=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout)
        return cp.returncode,cp.stdout.strip(),cp.stderr.strip()
    except (OSError,subprocess.SubprocessError) as exc:
        return None,"",f"{type(exc).__name__}: {exc}"


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--label",required=True)
    ap.add_argument("--out",required=True)
    args=ap.parse_args()

    receipt={
        "schema":SCHEMA,
        "provenance":{
            "requested_label":args.label,
            "run_id":os.environ.get("GITHUB_RUN_ID",""),
            "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
            "workflow_sha":os.environ.get("GITHUB_SHA",""),
            "image_os":os.environ.get("ImageOS"),
            "image_version":os.environ.get("ImageVersion"),
        },
        "runner":{"system":platform.system(),"machine":platform.machine()},
        "treatment":{
            "mlx_lm_version":MLX_LM_VERSION,
            "model_repo":MODEL_REPO,
            "requested_revision":MODEL_REVISION,
            "seed":SEED,
            "max_tokens":MAX_TOKENS,
            "prompt_sha256":sha256_bytes(PROMPT.encode()),
        },
        "classification":"INCONCLUSIVE",
        "reason":"",
        "warnings":[
            "runtime anchor only; this is not a model-quality qualification",
            "GHA GPU performance/capacity does not transfer to sovereign Apple Silicon",
            "local replay must mint a distinct environment identity",
        ],
    }

    if platform.system()!="Darwin" or platform.machine()!="arm64":
        receipt["classification"]="SKIPPED_GUARDRAIL"
        receipt["reason"]="MLX transfer anchor requires ARM64 macOS"
    else:
        py=sys.executable
        with tempfile.TemporaryDirectory(prefix="mlx-anchor-") as td:
            root=pathlib.Path(td)
            venv=root/"venv"
            rc,out,err=run([py,"-m","venv",str(venv)],timeout=90)
            if rc!=0:
                receipt["classification"]="HARNESS_FAILURE"
                receipt["reason"]="venv creation failed"
                receipt["venv"]={"exit_code":rc,"stderr":err[-2500:] or None}
            else:
                vpy=venv/"bin"/"python"
                rc,out,err=run([
                    str(vpy),"-m","pip","install","--disable-pip-version-check","--no-cache-dir",
                    f"mlx-lm=={MLX_LM_VERSION}"
                ],timeout=600)
                receipt["dependency_preparation"]={
                    "exit_code":rc,
                    "stdout":out[-2500:] or None,
                    "stderr":err[-3000:] or None,
                }
                if rc!=0:
                    receipt["classification"]="ENVIRONMENT_FAILURE"
                    receipt["reason"]="pinned mlx-lm installation failed"
                else:
                    child=root/"run_anchor.py"
                    child.write_text(r'''
import hashlib
import importlib.metadata
import json
import pathlib

import mlx.core as mx
from huggingface_hub import snapshot_download
from mlx_lm import generate
from mlx_lm.sample_utils import make_sampler
from mlx_lm.utils import load

MODEL_REPO="''' + MODEL_REPO + r'''"
MODEL_REVISION="''' + MODEL_REVISION + r'''"
PROMPT=''' + repr(PROMPT) + r'''
SEED=''' + str(SEED) + r'''
MAX_TOKENS=''' + str(MAX_TOKENS) + r'''

def sha256_file(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

mx.set_default_device(mx.gpu)
snapshot=snapshot_download(repo_id=MODEL_REPO,revision=MODEL_REVISION)
snapshot_path=pathlib.Path(snapshot)
resolved_revision=snapshot_path.name

files={}
for p in sorted(snapshot_path.rglob("*")):
    if p.is_file() and not p.is_symlink():
        files[str(p.relative_to(snapshot_path))]={
            "size":p.stat().st_size,
            "sha256":sha256_file(p),
        }

model,tokenizer=load(str(snapshot_path))
messages=[{"role":"user","content":PROMPT}]
if hasattr(tokenizer,"apply_chat_template") and tokenizer.chat_template is not None:
    formatted=tokenizer.apply_chat_template(messages,tokenize=False,add_generation_prompt=True)
else:
    formatted=PROMPT

def once():
    mx.random.seed(SEED)
    sampler=make_sampler(temp=0.0)
    text=generate(model,tokenizer,prompt=formatted,max_tokens=MAX_TOKENS,sampler=sampler,verbose=False)
    mx.synchronize()
    return text

a=once()
b=once()
evidence={
    "mlx_lm_version":importlib.metadata.version("mlx-lm"),
    "mlx_version":importlib.metadata.version("mlx"),
    "default_device":str(mx.default_device()),
    "resolved_revision":resolved_revision,
    "files":files,
    "output_a":a,
    "output_b":b,
    "output_a_sha256":hashlib.sha256(a.encode()).hexdigest(),
    "output_b_sha256":hashlib.sha256(b.encode()).hexdigest(),
    "nonempty":bool(a.strip()),
    "repeat_equal":a==b,
}
evidence["oracle"]=(
    evidence["mlx_lm_version"]=="''' + MLX_LM_VERSION + r'''" and
    "gpu" in evidence["default_device"].lower() and
    evidence["nonempty"] and
    evidence["repeat_equal"]
)
print(json.dumps(evidence,sort_keys=True))
''',encoding="utf-8")
                    rc,out,err=run([str(vpy),str(child)],timeout=600)
                    receipt["execution"]={"exit_code":rc,"stderr":err[-4000:] or None}
                    try:
                        evidence=json.loads(out.splitlines()[-1]) if out else None
                    except (json.JSONDecodeError,IndexError):
                        evidence=None
                    receipt["evidence"]=evidence
                    if rc!=0 or not isinstance(evidence,dict):
                        receipt["classification"]="HARNESS_FAILURE"
                        receipt["reason"]="MLX local-model anchor returned no parseable evidence"
                        receipt["execution"]["stdout"]=out[-3000:] or None
                    elif evidence.get("oracle"):
                        receipt["classification"]="SUPPORTED"
                        receipt["reason"]="pinned public model executed repeatable non-empty MLX-LM inference with GPU as the explicit default device"
                    else:
                        receipt["classification"]="ORACLE_FAILURE"
                        receipt["reason"]="model/runtime executed but deterministic GPU-default inference oracle was not satisfied"

    outpath=pathlib.Path(args.out)
    outpath.parent.mkdir(parents=True,exist_ok=True)
    outpath.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"MLX_LOCAL_MODEL_ANCHOR_RECEIPT={outpath}")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
