#!/usr/bin/env python3
"""Public-safe AAR Drive configuration/validation contract qualification."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, tempfile, zipfile

SCHEMA="aar-drive-adapter-contract/v1"
ROLES={
 "current-verified":"current","current-candidate":"current",
 "lineage":"lineage","superseded":"lineage","unknown-freshness":"lineage",
}
def parse_env_file(path:pathlib.Path)->dict[str,str]:
 out={}
 if not path.is_file(): return out
 for raw in path.read_text(encoding="utf-8-sig").splitlines():
  line=raw.strip()
  if not line or line.startswith("#") or "=" not in line: continue
  k,v=line.split("=",1); k=k.strip().removeprefix("export ").strip(); v=v.strip()
  if len(v)>=2 and v[0]==v[-1] and v[0] in "\"'": v=v[1:-1]
  if k and k.replace("_","a").isalnum(): out[k]=v
 return out
def discover(env_file:pathlib.Path)->dict:
 values=parse_env_file(env_file)
 names=["GOOGLE_DRIVE_CLIENT_ID","GOOGLE_DRIVE_CLIENT_SECRET","GOOGLE_DRIVE_REFRESH_TOKEN","GOOGLE_DRIVE_CURRENT_FOLDER_ID","GOOGLE_DRIVE_LINEAGE_FOLDER_ID","GOOGLE_DRIVE_AAR_ROOT_ID"]
 present={n:bool(os.environ.get(n) or values.get(n)) for n in names}
 return {"schema":SCHEMA,"operation":"status","credential_sources":{"process_environment":any(bool(os.environ.get(n)) for n in names),"env_file":env_file.is_file()},"configured":present,"live_oauth_ready":all(present[n] for n in names[:3]),"routing_ready":all(present[n] for n in names[3:])}
def plan(env_file:pathlib.Path)->dict:
 o=discover(env_file)
 return {"schema":SCHEMA,"operation":"plan","action":"live-verify" if o["live_oauth_ready"] and o["routing_ready"] else "credential-boundary","changed":False,"observation":o}
def contract()->dict:
 return {"schema":SCHEMA,"audiences":{"human":{"commands":["status","plan","contract"],"default_output":"human"},"automation":{"output":"json","success_signal":"configured/live_oauth_ready"},"agent":{"discover":"contract","observe":"status","plan":"plan","preferred_output":"json"}},"roles":ROLES,"secret_boundary":"No credential value or folder ID is emitted; public qualification expects credential-boundary.","properties":["cross-platform","read-only discovery","fail-closed","no secret echo"]}
def selftest()->dict:
 with tempfile.TemporaryDirectory() as td:
  p=pathlib.Path(td)/"x.env"; p.write_text("# x\nexport GOOGLE_DRIVE_CLIENT_ID='id'\nGOOGLE_DRIVE_CURRENT_FOLDER_ID=current\n",encoding="utf-8")
  parsed=parse_env_file(p)
  assert parsed=={"GOOGLE_DRIVE_CLIENT_ID":"id","GOOGLE_DRIVE_CURRENT_FOLDER_ID":"current"}
  assert ROLES["current-candidate"]=="current" and ROLES["lineage"]=="lineage"
  o=discover(pathlib.Path(td)/"missing.env")
  assert not o["credential_sources"]["env_file"]
 return {"schema":SCHEMA,"operation":"selftest","passed":True}
def human(v):
 if v.get("operation")=="status": return f"Drive config: oauth={'ready' if v['live_oauth_ready'] else 'credential-boundary'}, routing={'ready' if v['routing_ready'] else 'credential-boundary'}"
 if v.get("operation")=="plan": return f"Drive plan: {v['action']}"
 return json.dumps(v,indent=2,sort_keys=True)
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("command",choices=["status","plan","contract","selftest"]); ap.add_argument("--env-file",type=pathlib.Path,default=pathlib.Path(".local/etc/aar-drive-corpus.env")); ap.add_argument("--output",choices=["human","json"],default="human"); a=ap.parse_args()
 v=discover(a.env_file) if a.command=="status" else plan(a.env_file) if a.command=="plan" else contract() if a.command=="contract" else selftest()
 print(json.dumps(v,indent=2,sort_keys=True) if a.output=="json" else human(v)); return 0
if __name__=="__main__": raise SystemExit(main())
