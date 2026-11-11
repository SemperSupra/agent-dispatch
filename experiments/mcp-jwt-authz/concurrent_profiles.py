#!/usr/bin/env python3
"""Synthetic same-principal concurrent login contexts against actual gateway.
Proves selected upstream isolation and restart reconstruction, not real OAuth.
"""
import argparse,json,pathlib,threading,time
from concurrent.futures import ThreadPoolExecutor
import make_issuer
from fixture import call,permitted
CASES={"research-a":("research","alpha_echo","beta_echo"),
       "engineering-b":("engineering","beta_echo","alpha_echo"),
       "research-c":("research","alpha_echo","beta_echo"),
       "invalid-d":("unknown",None,"alpha_echo")}
def run_one(name,belt,own,other,token,rounds,barrier):
    init={"protocolVersion":"2025-06-18","capabilities":{},
          "clientInfo":{"name":"synthetic-"+name,"version":"1"}}
    status,result,session=call("initialize",1,token,params=init)
    if status!=200 or "result" not in result:raise AssertionError((name,"init",status))
    barrier.wait(timeout=20)
    n=0
    for rep in range(rounds):
        status,result,session=call("tools/list",rep*10+2,token,session)
        names=sorted(t["name"] for t in result.get("result",{}).get("tools",[]))
        if status!=200 or names!=([own] if own else []):
            raise AssertionError((name,"list",rep,status,names))
        n+=1
        if own:
            status,result,session=call("tools/call",rep*10+3,token,session,
                                      {"name":own,"arguments":{"text":name+":"+str(rep)}})
            if not permitted(status,result,own.split("_")[0]+":"+name+":"+str(rep)):
                raise AssertionError((name,"own",rep,status))
            n+=1
        status,result,session=call("tools/call",rep*10+4,token,session,
                                  {"name":other,"arguments":{"text":"forbidden"}})
        if permitted(status,result,other.split("_")[0]+":forbidden"):
            raise AssertionError((name,"forbidden",rep,status))
        n+=1
    return {"context":name,"belt":belt,"assertions":n,"passed":True}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--tokens-dir",default="synthetic-contexts")
    p.add_argument("--reuse-tokens",action="store_true")
    p.add_argument("--rounds",type=int,default=12)
    p.add_argument("--out",default="concurrent-receipt.json")
    a=p.parse_args()
    assert 1<=a.rounds<=100
    folder=pathlib.Path(a.tokens_dir);folder.mkdir(exist_ok=True)
    result={"schema":"m1-concurrent-login-context-v1","principal":"alpha",
            "contexts":len(CASES),"rounds":a.rounds,"reusedTokens":a.reuse_tokens,
            "results":[],"passed":False,
            "limitations":["synthetic issuer, not live login","legacy 2025 MCP transport",
                           "no saved belt CRUD or live revocation"]}
    try:
        tokens={}
        for key,(belt,_,_) in CASES.items():
            file=folder/(key+".jwt")
            if a.reuse_tokens:tokens[key]=file.read_text()
            else:
                now=int(time.time())
                tokens[key]=make_issuer.sign({"iss":"https://issuer.invalid/m1",
                  "aud":"m1-synthetic-client","sub":"alpha","client_id":key,
                  "belt":belt,"iat":now,"exp":now+600})
                file.write_text(tokens[key]);file.chmod(0o600)
        barrier=threading.Barrier(len(CASES))
        with ThreadPoolExecutor(max_workers=len(CASES)) as pool:
            futures=[pool.submit(run_one,key,*v,tokens[key],a.rounds,barrier)
                     for key,v in CASES.items()]
            result["results"]=[f.result(timeout=80) for f in futures]
        result["assertions"]=sum(x["assertions"] for x in result["results"])
        result["passed"]=len(result["results"])==len(CASES) and all(x["passed"] for x in result["results"])
    except Exception as e:result["error"]=repr(e)
    pathlib.Path(a.out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["passed"] else 1
if __name__=="__main__":raise SystemExit(main())
