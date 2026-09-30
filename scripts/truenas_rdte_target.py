#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, pathlib, re, shlex, sys

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

class TargetError(RuntimeError):
    pass

def load_registry(path: pathlib.Path):
    try:
        doc=json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TargetError(f"cannot read target registry: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != "gha-kvm-truenas-targets/v1":
        raise TargetError("unsupported target registry schema")
    targets=doc.get("targets")
    if not isinstance(targets, list) or not targets:
        raise TargetError("target registry has no targets")
    seen=set()
    result={}
    for i,t in enumerate(targets):
        if not isinstance(t, dict):
            raise TargetError(f"targets[{i}] must be an object")
        version=t.get("version")
        if not isinstance(version,str) or not version or version in seen:
            raise TargetError(f"invalid or duplicate target version at index {i}")
        seen.add(version)
        for key in ("system_version","iso_name","iso_url","sha256_url","middleware_ref","middleware_commit","foundry_profile","ha_apps_gate"):
            if not isinstance(t.get(key),str) or not t[key]:
                raise TargetError(f"{version}: missing {key}")
        if not SHA_RE.fullmatch(t["middleware_commit"]):
            raise TargetError(f"{version}: middleware_commit must be exact 40-hex")
        if any(token in t["iso_url"].lower() for token in ("latest","nightly","master+")):
            raise TargetError(f"{version}: supported target ISO must be exact, not floating")
        if t["sha256_url"] != t["iso_url"] + ".sha256":
            raise TargetError(f"{version}: sha256_url must be exact ISO sidecar")
        result[version]=t
    return result

def shell(target):
    fields={
      "VERSION":target["version"],
      "EXPECTED_SYSTEM_VERSION":target["system_version"],
      "ISO_NAME":target["iso_name"],
      "ISO_URL":target["iso_url"],
      "SHA_URL":target["sha256_url"],
      "MIDDLEWARE_REF":target["middleware_ref"],
      "MIDDLEWARE_COMMIT":target["middleware_commit"],
      "FOUNDRY_PROFILE":target["foundry_profile"],
      "HA_APPS_GATE":target["ha_apps_gate"],
      "AUTHORITY_ISSUE":str(target.get("authority_issue","")),
    }
    return "\n".join(f"{k}={shlex.quote(v)}" for k,v in fields.items())

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--registry", type=pathlib.Path, required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--shell", action="store_true")
    a=p.parse_args()
    try:
        targets=load_registry(a.registry)
        if a.version not in targets:
            raise TargetError(f"exact TrueNAS target is not registered: {a.version}")
        target=targets[a.version]
        print(shell(target) if a.shell else json.dumps(target, indent=2, sort_keys=True))
        return 0
    except TargetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
