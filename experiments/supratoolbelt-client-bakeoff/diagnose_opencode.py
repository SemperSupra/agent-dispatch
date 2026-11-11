#!/usr/bin/env python3
"""OpenCode V2 cold MCP registry investigation (C0/C1), synthetic and no LLM keys.

Tests exact global/project config, debug config, delayed MCP readiness; compares
source-intended shape to actual running CLI state without claiming production fit.
"""
import json,os,pathlib,subprocess,sys,time
ROOT=pathlib.Path(os.environ["RUNNER_TEMP"]).joinpath("supra-opencode-diagnostic")
HOME=ROOT/"home";WORK=ROOT/"work"
URL="http://127.0.0.1:39200/mcp"
def execute(args,timeout=40):
 env=os.environ.copy()
 env.update({"HOME":str(HOME),"XDG_CONFIG_HOME":str(HOME/".config"),
            "XDG_DATA_HOME":str(HOME/".local/share"),"XDG_CACHE_HOME":str(HOME/".cache"),
            "OPENCODE_DISABLE_AUTOUPDATE":"true","CI":"true","NO_COLOR":"1"})
 p=subprocess.run(["opencode",*args],cwd=WORK,env=env,text=True,
                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 return p.returncode,(p.stdout+"\n"+p.stderr)[:3000]
def main():
 ROOT.mkdir(parents=True,exist_ok=True);HOME.mkdir(parents=True,exist_ok=True);WORK.mkdir(parents=True,exist_ok=True)
 target=WORK/"opencode.json"
 target.write_text(json.dumps({"$schema":"https://opencode.ai/config.json",
   "mcp":{"servers":{"supra-toolbelt":{"type":"remote","url":URL,
         "oauth":False,"protocol":"legacy"}}}},indent=2)+"\n")
 # source-directory validation is explicit: process cwd must be the test workspace, not checked-out Git root.
 report={"schema":"supra-opencode-coldstart-diagnostic-v1","passed":False,
   "configurationSource":str(target.relative_to(ROOT)),"observations":[],
   "limits":["synthetic loopback 2025 MCP upstream","no model login/inference",
             "does not establish OAuth, belt authorization or privileged tool use"]}
 try:
  rc,out=execute(["--version"]);report["version"]=out.strip()[:100]
  rc,dbg=execute(["debug","config"]);report["debugConfigExit"]=rc
  report["debugContainsTarget"]="supra-toolbelt" in dbg
  if rc:report["debugExcerpt"]=dbg[-400:]
  # The official V2 CLI has a reported cold registry race (upstream issue #62902).
  for trial in range(1,8):
   rc,out=execute(["mcp","list"])
   entry={"rep":trial,"exit":rc,"listsTarget":"supra-toolbelt" in out.lower(),
          "isConnected":"connected" in out.lower(),"noServers":"no mcp servers configured" in out.lower(),
          "outputSample":out[:220]}
   report["observations"].append(entry)
   if entry["listsTarget"] and entry["isConnected"] and rc==0:
    report["passed"]=True;break
   time.sleep(2)
  if not report["passed"]:
   rc,details=execute(["mcp","list","--print-logs"])
   report["logModeExit"]=rc
   report["logModeListsTarget"]="supra-toolbelt" in details.lower()
   report["logModeSample"]=details[-750:]
  report["resolvedByRetry"]=report["passed"] and len(report["observations"])>1
  report["passed"]=bool(report["passed"])
 except Exception as e:report["failure"]=repr(e)[:500]
 pathlib.Path("opencode-diagnostic-receipt.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
 print(json.dumps(report,indent=2,sort_keys=True))
 return 0 if report["passed"] else 1
if __name__=="__main__":sys.exit(main())
