#!/usr/bin/env python3
"""Actual JWT-claim-selected target tests; not persistent belt management."""
import json,pathlib,time,sys
import make_issuer
from fixture import call,permitted
def issue_belt(subject,belt):
 now=int(time.time())
 token=make_issuer.sign({"iss":"https://issuer.invalid/m1","aud":"m1-synthetic-client",
   "sub":subject,"belt":belt,"iat":now,"exp":now+600})
 return token
def run_profile(belt,expected):
 token=issue_belt("alpha",belt)
 params={"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"profile-probe-"+belt,"version":"1"}}
 status,body,session=call("initialize",1,token,params=params)
 if status!=200 or "result" not in body:return False,{"reason":"initialize","status":status}
 status,body,session=call("tools/list",2,token,session)
 names=sorted(t.get("name") for t in body.get("result",{}).get("tools",[]))
 if names!=expected:return False,{"reason":"discovery","names":names,"expected":expected}
 if expected:
  name=expected[0];source=name.split("_")[0]
  status,body,session=call("tools/call",3,token,session,{"name":name,"arguments":{"text":"profile"}})
  if not permitted(status,body,source+":profile"):return False,{"reason":"own call","status":status}
  forbidden="beta_echo" if source=="alpha" else "alpha_echo"
  status,body,session=call("tools/call",4,token,session,{"name":forbidden,"arguments":{"text":"forbidden"}})
  if permitted(status,body,forbidden.split("_")[0]+":forbidden"):return False,{"reason":"cross-scope invoke"}
 return True,{"belt":belt,"names":names}
def main():
 out={"schema":"m1-authenticated-target-selection-v1","checks":[],"passed":False}
 try:
  # First user session with Research belt; another session with same principal selects Engineering;
  # first session retains Research selection; no global mutation.
  cases=[("research",["alpha_echo"]),("engineering",["beta_echo"]),
         ("research",["alpha_echo"]),("invalid",[])]
  for belt,expected in cases:
   ok,detail=run_profile(belt,expected)
   out["checks"].append({"belt":belt,"passed":ok,"detail":detail})
  out["passed"]=len(out["checks"])==4 and all(x["passed"] for x in out["checks"])
 except Exception as e:out["error"]=repr(e)
 pathlib.Path("profile-receipt.json").write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
 print(json.dumps(out,indent=2,sort_keys=True))
 return 0 if out["passed"] else 1
if __name__=="__main__":sys.exit(main())
