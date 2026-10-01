#!/usr/bin/env python3
import argparse,json,os,queue,subprocess,tempfile,threading,time
from pathlib import Path

AUTH_ENV_NAMES=("ACCESS_TOKEN","OPENAI_API_KEY","CODEX_API_KEY","OPENAI_ACCESS_TOKEN","CHATGPT_ACCESS_TOKEN")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--codex",required=True)
    ap.add_argument("--output",required=True)
    ap.add_argument("--timeout",type=float,default=10.0)
    a=ap.parse_args()

    env=os.environ.copy()
    for name in AUTH_ENV_NAMES:
        env.pop(name,None)
    home=tempfile.mkdtemp(prefix="suprachat-account-read-guest-")
    env["CODEX_HOME"]=home
    env["XDG_CONFIG_HOME"]=str(Path(home)/"xdg-config")
    env["XDG_DATA_HOME"]=str(Path(home)/"xdg-data")

    cmd=[
        a.codex,"app-server","--listen","stdio://",
        "-c",'model_provider="openai_chatgpt_plan"',
        "-c",'model_providers.openai_chatgpt_plan.name="ChatGPT plan"',
        "-c",'model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"',
        "-c",'model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN"',
        "-c",'model_providers.openai_chatgpt_plan.wire_api="responses"',
        "-c","model_providers.openai_chatgpt_plan.requires_openai_auth=false",
        "-c","model_providers.openai_chatgpt_plan.supports_websockets=false",
    ]
    p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1,env=env)
    q=queue.Queue(); stderr=[]
    def rdout():
        for line in p.stdout: q.put(line.rstrip("\r\n"))
        q.put(None)
    def rderr():
        for line in p.stderr:
            stderr.append(line.rstrip("\r\n"))
            if len(stderr)>100: del stderr[:25]
    threading.Thread(target=rdout,daemon=True).start()
    threading.Thread(target=rderr,daemon=True).start()

    next_id=1
    denied=[]
    def send(obj):
        p.stdin.write(json.dumps(obj,separators=(",",":"))+"\n"); p.stdin.flush()
    def req(method,params):
        nonlocal next_id
        rid=str(next_id); next_id+=1
        payload={"id":rid,"method":method}
        if params is not None: payload["params"]=params
        send(payload)
        deadline=time.monotonic()+a.timeout
        while time.monotonic()<deadline:
            try: line=q.get(timeout=max(.05,deadline-time.monotonic()))
            except queue.Empty: break
            if line is None: break
            try: msg=json.loads(line)
            except Exception: continue
            if msg.get("id") is not None and msg.get("method") is not None:
                denied.append(msg.get("method"))
                send({"id":msg["id"],"error":{"code":-32000,"message":"guest probe denies server requests"}})
                continue
            if str(msg.get("id"))!=rid: continue
            if "error" in msg:
                e=msg["error"] if isinstance(msg["error"],dict) else {"message":str(msg["error"])}
                m=str(e.get("message",""))
                low=m.lower()
                outcome="AUTH_REQUIRED" if any(x in low for x in ("auth","login","token","credential","unauthorized","forbidden")) else "ERROR"
                return {"outcome":outcome,"error_code":e.get("code"),"error_message":m[:500]}
            result=msg.get("result")
            return {"outcome":"RESULT","result":result}
        return {"outcome":"TIMEOUT"}

    evidence={"schema":"suprachat-codex-account-read-guest/v1",
              "credentials_provided":False,
              "removed_environment_names":list(AUTH_ENV_NAMES),
              "initialize":None,"account_read":None,"server_requests_denied":[]}
    try:
        evidence["initialize"]=req("initialize",{
            "clientInfo":{"name":"suprachat-account-read-guest","title":"SupraChat account/read guest probe","version":"0.1.0"},
            "capabilities":{"experimentalApi":True}})
        if evidence["initialize"].get("outcome")=="RESULT":
            send({"method":"initialized"})
            evidence["account_read"]=req("account/read",{})
    finally:
        evidence["server_requests_denied"]=sorted(set(denied))
        try: p.stdin.close()
        except Exception: pass
        try:
            p.terminate(); p.wait(timeout=3)
        except Exception:
            try: p.kill()
            except Exception: pass
        evidence["stderr_tail"]=stderr[-20:]

    Path(a.output).parent.mkdir(parents=True,exist_ok=True)
    Path(a.output).write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    public={
        "schema":evidence["schema"],
        "initialize_outcome":evidence["initialize"].get("outcome") if evidence["initialize"] else None,
        "account_read_outcome":evidence["account_read"].get("outcome") if evidence["account_read"] else None,
        "account_read_result_keys":sorted((evidence["account_read"].get("result") or {}).keys()) if evidence["account_read"] and isinstance(evidence["account_read"].get("result"),dict) else [],
        "requires_openai_auth":(evidence["account_read"].get("result") or {}).get("requiresOpenaiAuth") if evidence["account_read"] and isinstance(evidence["account_read"].get("result"),dict) else None,
        "account_present":((evidence["account_read"].get("result") or {}).get("account") is not None) if evidence["account_read"] and isinstance(evidence["account_read"].get("result"),dict) else None,
        "server_requests_denied":evidence["server_requests_denied"]
    }
    print(json.dumps(public,indent=2,sort_keys=True))
    return 0 if evidence["initialize"].get("outcome")=="RESULT" and evidence["account_read"] and evidence["account_read"].get("outcome")!="TIMEOUT" else 2

if __name__=="__main__":
    raise SystemExit(main())
