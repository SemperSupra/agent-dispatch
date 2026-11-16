"""Real native etcd v3 atomic gateway admission, synthetic effects only.

No live executor is called. The commit-time transaction is what is proven:
epoch check + budget decrement + idempotency/UNKNOWN receipt in one etcd revision.
The external effect after this transaction remains UNFENCED/NOT_TESTED.
"""
import base64
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from txn_test import b, post, get

def put(key, value):
    r=post(2379,"put",{"key":b(key),"value":b(value)})
    assert "header" in r,r

def atomic(port, epoch, budget_key, effect_key):
    compares=[
      {"target":"VALUE","key":b("r62/gateway/epoch"),"value":b(epoch),"result":"EQUAL"},
      {"target":"VALUE","key":b(budget_key),"value":b("1"),"result":"EQUAL"},
      {"target":"VERSION","key":b(effect_key),"version":"0","result":"EQUAL"}]
    puts=[
      {"request_put":{"key":b(budget_key),"value":b("0")}},
      {"request_put":{"key":b(effect_key),"value":b("UNKNOWN")}}]
    r=post(port,"txn",{"compare":compares,"success":puts,
       "failure":[{"request_range":{"key":b(effect_key)}}]})
    assert "header" in r,r
    return r.get("succeeded") is True

def swap_epoch(before,after):
    r=post(2379,"txn",{"compare":[{"target":"VALUE","key":b("r62/gateway/epoch"),
        "value":b(before),"result":"EQUAL"}],
        "success":[{"request_put":{"key":b("r62/gateway/epoch"),"value":b(after)}}],
        "failure":[]})
    assert "header" in r and r.get("succeeded") is True,r

def main():
    put("r62/gateway/epoch","epoch-001")
    committed={}
    for i in range(40):
        budget=f"r62/gateway/budget/{i}"
        put(budget,"1")
        ready=Barrier(2)
        def compete(port,actor):
            ready.wait(timeout=10)
            key=f"r62/gateway/effects/{i}-{actor}"
            return actor,atomic(port,"epoch-001",budget,key)
        with ThreadPoolExecutor(max_workers=2) as pool:
            fa=pool.submit(compete,2379,"a")
            fb=pool.submit(compete,22379,"b")
            a,b_result=fa.result(timeout=10),fb.result(timeout=10)
        outcomes=[a,b_result]
        assert sum(int(x[1]) for x in outcomes)==1,outcomes
        winner=next(name for name,okay in outcomes if okay)
        effect=f"r62/gateway/effects/{i}-{winner}"
        assert get(2379,budget)==["0"],budget
        assert get(2379,effect)==["UNKNOWN"],effect
        # Lost ACK / duplicate key cannot reserve again.
        assert not atomic(2379,"epoch-001",budget,effect)
        committed[i]=(budget,effect)
    swap_epoch("epoch-001","epoch-002")
    # Old-primary replay and new-primary overclaim both fail closed.
    for i,(budget,effect) in committed.items():
        assert not atomic(2379,"epoch-001",budget,f"r62/gateway/stale/{i}")
        assert not atomic(22379,"epoch-002",budget,f"r62/gateway/replay/{i}")
        assert get(2379,effect)==["UNKNOWN"],effect
    # EXPECTED RED: privileged old-epoch rollback makes old-authority
    # look current; a new empty budget can then be accepted again.
    put("r62/gateway/budget/rollback","1")
    swap_epoch("epoch-002","epoch-001")  # Dangerous explicit test-only rollback
    assert atomic(2379,"epoch-001","r62/gateway/budget/rollback","r62/gateway/reset-old-writer")
    # No external effect was attempted. This is NOT a real sink fence.
    print(json.dumps({"provider":"actual-native-etcd-v3","gateway":"synthetic-only",
       "races":40,"exactly_one_per_budget":40,"duplicate_key":"DENIED",
       "stale_epoch":"DENIED","new_owner_overclaim":"DENIED",
       "unknown_liability":"RETAINED","privileged_epoch_reset":"EXPECTED_RED_ABA",
       "external_effect_sink":"NOT_TESTED","independent_identity":"NOT_TESTED",
       "cross_host":"NOT_TESTED","passed":True},sort_keys=True))
if __name__=="__main__":main()
