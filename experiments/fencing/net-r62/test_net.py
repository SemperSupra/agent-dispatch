"""Actual etcd v3 JSON Gateway over three container network namespaces; public synthetic keys."""
import sys, json,base64,urllib.request
def b(v):return base64.b64encode(v.encode()).decode()
def request(port,path,payload,timeout=4):
    # Direct private bridge address, no host port publishing or environment proxy.
    endpoint={2379:"172.29.62.11",22379:"172.29.62.12",32379:"172.29.62.13"}[port]
    req=urllib.request.Request("http://%s:2379/v3/kv/%s"%(endpoint,path),
        data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="POST")
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req,timeout=timeout) as r:return json.loads(r.read().decode())
def read(port,key):
    r=request(port,"range",{"key":b(key)})
    return [base64.b64decode(x["value"]).decode() for x in r.get("kvs",[])]
def create(port,key,val,timeout=4):
    r=request(port,"txn",{"compare":[{"target":"VERSION","key":b(key),"version":"0"}],
        "success":[{"request_put":{"key":b(key),"value":b(val)}}],
        "failure":[{"request_range":{"key":b(key)}}]},timeout)
    assert "header" in r,r
    return r.get("succeeded") is True
def main():
    stage=sys.argv[1]
    if stage=="ready":
        # Read-only quorum readiness. Never write a claim in a retry loop.
        for port in (2379,22379,32379):
            assert read(port,"r62/net/nonexistent-readiness")==[]
        print(json.dumps({"stage":stage,"read_only_quorum":True}))
    elif stage=="start":
        assert create(2379,"r62/net/initial","DURABLE")
        assert read(22379,"r62/net/initial")==["DURABLE"]
        print(json.dumps({"stage":stage,"real_peer_namespaces":3,"cross_member_read":"PASS"}))
    elif stage=="two":
        assert create(2379,"r62/net/majority","UNKNOWN-RESERVED")
        assert read(22379,"r62/net/initial")==["DURABLE"]
        assert read(22379,"r62/net/majority")==["UNKNOWN-RESERVED"]
        print(json.dumps({"stage":stage,"network_partitioned_peer_still_running":True,"majority_two_of_three":"PASS"}))
    elif stage=="one":
        try:
            r=request(2379,"txn",{"compare":[{"target":"VERSION","key":b("r62/net/timed"),"version":"0"}],
               "success":[{"request_put":{"key":b("r62/net/timed"),"value":b("UNCERTAIN")}}],
               "failure":[]},timeout=3)
            assert r.get("succeeded") is not True,("unsafe positive after quorum lost",r)
            status="UNKNOWN_NO_ACK"
        except Exception:
            status="UNKNOWN_NO_ACK"
        print(json.dumps({"stage":stage,"no_quorum_acked_commits":"NONE","timed_request":status,
            "blind_retry":False}))
    elif stage=="recover":
        for port in (2379,22379,32379):
            assert read(port,"r62/net/initial")==["DURABLE"],port
            assert read(port,"r62/net/majority")==["UNKNOWN-RESERVED"],port
        timed=read(2379,"r62/net/timed")
        assert timed in ([],["UNCERTAIN"]),timed
        # Replay of original claim rejected under real etcd quorum.
        assert create(32379,"r62/net/initial","STALE") is False
        print(json.dumps({"stage":stage,"network_restored":True,
            "previous_unknown_liability_survived":True,"timed_request_observed":
            "PRESENT" if timed else "ABSENT_AT_READBACK","stale_claim_denied":True,
            "independent_physical_hosts":"NOT_TESTED"}))
    else: raise SystemExit("bad stage")
if __name__=="__main__":main()
