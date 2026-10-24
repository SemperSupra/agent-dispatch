#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from truenas_session_manifest import SessionError, validate_manifest

def load_json(path: pathlib.Path):
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise SessionError(f"{path}: top-level value must be an object")
    return value

def provider_map(path: pathlib.Path):
    doc=load_json(path)
    if doc.get("schema")!="truenas-capsule-providers/v1":
        raise SessionError("unsupported capsule provider registry schema")
    return {x["id"]:x for x in doc.get("providers",[])}

def lower_single(manifest_path, targets_path, providers_path):
    validated=validate_manifest(manifest_path,targets_path,providers_path)
    manifest=load_json(manifest_path)
    capsules=manifest["capsules"]
    if len(capsules)!=1:
        raise SessionError("single-capsule equivalence adapter requires exactly one capsule")
    capsule=capsules[0]
    provider=provider_map(providers_path).get(capsule["provider"])
    if not provider:
        raise SessionError(f"unregistered provider: {capsule['provider']}")
    selector=provider.get("existing_selector")
    artifact=provider.get("control_artifact")
    probe=provider.get("probe")
    if not all(isinstance(x,str) and x for x in (selector,artifact,probe)):
        raise SessionError("provider lacks existing execution binding")
    return {
        "schema":"truenas-single-capsule-lowering/v1",
        "session_id":validated["session_id"],
        "manifest_sha256":validated["manifest_sha256"],
        "version":validated["version"],
        "capsule_id":capsule["id"],
        "provider":capsule["provider"],
        "existing_selector":selector,
        "control_artifact":artifact,
        "probe":probe,
        "authority":capsule["authority"],
        "runtime_semantics_changed":False,
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",type=pathlib.Path,required=True)
    p.add_argument("--targets",type=pathlib.Path,default=pathlib.Path("config/truenas-rdte-targets.json"))
    p.add_argument("--providers",type=pathlib.Path,default=pathlib.Path("config/truenas-capsule-providers.json"))
    a=p.parse_args()
    try:
        print(json.dumps(lower_single(a.manifest,a.targets,a.providers),indent=2,sort_keys=True))
        return 0
    except (SessionError,OSError,json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
