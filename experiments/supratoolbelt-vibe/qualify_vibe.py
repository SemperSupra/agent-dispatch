#!/usr/bin/env python3
"""Vibe C0: real native MCP add/remove in disposable HOME contexts, no model login."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

NAMES = {
    "research": "SUPRATOOLBELT_RESEARCH_RDTE_TOKEN",
    "engineering": "SUPRATOOLBELT_ENGINEERING_RDTE_TOKEN",
}
URL = "http://127.0.0.1:39200/mcp"

def cli(home, *args):
    env=dict(os.environ)
    env["HOME"]=str(home)
    env["XDG_CONFIG_HOME"]=str(home / ".config")
    env["XDG_CACHE_HOME"]=str(home / ".cache")
    env["CI"]="true"
    env["NO_COLOR"]="1"
    proc=subprocess.run(["vibe",*args],capture_output=True,text=True,env=env,timeout=60)
    if proc.returncode:
        raise RuntimeError("vibe cmd "+repr(args)+" failed: "+proc.stderr[-450:])
    return proc.stdout+proc.stderr

def main():
    root=Path("vibe-test-homes").absolute()
    root.mkdir(exist_ok=True)
    receipt={"schema":"m1-vibe-cli-config-rdte-v1","profiles":{},
             "passed":False,
             "limitations":["No model login/inference","No remote MCP connection or tool call",
                            "No real OAuth or service authorization"]}
    try:
        receipt["version"]=cli(root,"--version").strip()[:140]
        for name,envref in NAMES.items():
            home=root/name
            home.mkdir()
            cli(home,"mcp","add","supra-toolbelt","--transport","http",
                "--url",URL,"--api-key-env",envref)
            config=home/".vibe"/"config.toml"
            if not config.exists():raise AssertionError("Vibe config not written")
            s=config.read_text()
            if "synthetic-secret-value" in s:raise AssertionError("secret persisted")
            obj=tomllib.loads(s)
            found=[x for x in obj.get("mcp_servers",[]) if x.get("name")=="supra-toolbelt"]
            if len(found)!=1:raise AssertionError("server not registered")
            item=found[0]
            if item.get("url")!=URL:raise AssertionError("server URL mismatch")
            auth=item.get("auth",item)
            if auth.get("api_key_env")!=envref:
                raise AssertionError("auth did not point to environment variable")
            receipt["profiles"][name]={"url":URL,"authEnvRef":envref,
                                        "nativeConfig":".vibe/config.toml","registered":True}
        cli(root/"research","mcp","remove","supra-toolbelt")
        other=tomllib.loads((root/"engineering"/".vibe"/"config.toml").read_text())
        if not any(x.get("name")=="supra-toolbelt" for x in other.get("mcp_servers",[])):
            raise AssertionError("removing research changed engineering")
        receipt["passed"]=len(receipt["profiles"])==2
    except Exception as e:
        receipt["error"]=repr(e)[:900]
    Path("vibe-client-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0 if receipt["passed"] else 1
if __name__=="__main__":sys.exit(main())
