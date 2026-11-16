"""Public-safe actual etcd V3 HTTP gateway transaction qualification; loopback only."""
import sys,json,base64,time,urllib.request
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

def b(text):
    return base64.b64encode(text.encode()).decode()

def post(port,method,payload,timeout=3):
    req=urllib.request.Request("http://127.0.0.1:%s/v3/kv/%s"%(port,method),
        data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=timeout) as r:
        return json.loads(r.read().decode())

def txn(port,key,value,timeout=3):
    return post(port,"txn",{
        "compare":[{"target":"VERSION","key":b(key),"version":"0"}],
        "success":[{"request_put":{"key":b(key),"value":b(value)}}],
        "failure":[{"request_range":{"key":b(key)}}]},timeout)

def get(port,key):
    x=post(port,"range",{"key":b(key)},timeout=5)
    return [base64.b64decode(z["value"]).decode() for z in x.get("kvs",[])]

def retry_txn(port,key,value):
    err=None
    for _ in range(15):
        try:return txn(port,key,value)
        except Exception as e:
            err=e;time.sleep(1)
    raise AssertionError("2/3 quorum failed after bounded retry: %s"%str(err))

def main():
    mode=sys.argv[1]
    if mode=="race":
        gate=Barrier(2)
        def contender(port,owner):
            gate.wait(timeout=10)
            r=txn(port,"r61/claim",owner)
            assert "header" in r,("invalid etcd txn response",owner,r)
            return owner,r.get("succeeded") is True
        with ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(contender,2379,"A");c=pool.submit(contender,22379,"B")
            results=[a.result(timeout=10),c.result(timeout=10)]
        assert sorted([r[1] for r in results])==[False,True],results
        winner=next(owner for owner,ok in results if ok)
        assert get(2379,"r61/claim")==[winner]
        print(json.dumps({"stage":mode,"one_winner":True,"winner":winner,"server":"native-etcd-3-peer-one-runner"}))
    elif mode=="quorum2":
        r=retry_txn(2379,"r61/after-peer-loss","UNKNOWN-liability")
        assert r.get("succeeded") is True,r
        assert get(2379,"r61/claim") in (["A"],["B"])
        print(json.dumps({"stage":mode,"two_of_three_commit":"PASS"}))
    elif mode=="noquorum":
        try:
            r=txn(2379,"r61/no-quorum","MAYBE",timeout=3)
            assert r.get("succeeded") is not True,("unacceptable no-quorum success",r)
            status="DENIED_NO_ACK" if r.get("succeeded") is False else "UNKNOWN_NO_ACK"
        except Exception as e:
            status="UNKNOWN_NO_ACK"
        print(json.dumps({"stage":mode,"outcome":status,"never_retry_unknown_automatically":True}))
    elif mode=="recovered":
        assert get(2379,"r61/claim") in (["A"],["B"])
        assert get(2379,"r61/after-peer-loss")==["UNKNOWN-liability"]
        possibly_committed=get(2379,"r61/no-quorum")
        assert possibly_committed in ([],["MAYBE"]),possibly_committed
        replay=retry_txn(2379,"r61/claim","STALE")
        assert "header" in replay and replay.get("succeeded") is not True,replay
        print(json.dumps({"stage":mode,"previous_liability_retained":True,
            "post_timeout_receipt": "PRESENT" if possibly_committed else "ABSENT_AT_READBACK",
            "stale_absent_version_denied":True,"physical_cross_host":"NOT_TESTED"}))
    else: raise SystemExit("unknown mode")
if __name__=="__main__":main()
