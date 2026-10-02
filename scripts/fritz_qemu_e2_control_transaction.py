#!/usr/bin/env python3
"""E2-R8: classify the already-proven svctl↔supervisor control exchange."""
from __future__ import annotations
import argparse, importlib.util, json, pathlib

_R6=pathlib.Path(__file__).with_name("fritz_qemu_e2_svctl_start_ctlmgr.py")
_SPEC=importlib.util.spec_from_file_location("fritz_qemu_e2_svctl_start_ctlmgr",_R6)
if _SPEC is None or _SPEC.loader is None: raise RuntimeError("unable to load R6")
r6=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(r6)

SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-control-transaction/v1"


def exchange_present(call:dict|None)->bool:
    if not isinstance(call,dict):return False
    t=call.get("controlIoTrace",{})
    calls=t.get("calls",{})
    b=t.get("bytes",{})
    return bool(
        calls.get("connect",0)
        and (
            b.get("write",0) or b.get("send",0)
            or b.get("read",0) or b.get("recv",0)
        )
    )


def classify(rt:dict)->str:
    if rt.get("ctlmgrProcessObserved"):return "E2_R8_CTLMGR_PROCESS_OBSERVED"
    start=rt.get("start",{})
    if start.get("exitCode") not in (0,None):return "E2_R8_START_REJECTED"
    if isinstance(start,dict) and exchange_present(start):
        if rt.get("statusChanged"):return "E2_R8_EXCHANGE_STATUS_CHANGED_NO_PROCESS"
        return "E2_R8_CONTROL_EXCHANGE_NO_STATE_TRANSITION"
    if start.get("exitCode")==0:return "E2_R8_START_EXIT_ZERO_NO_EXCHANGE_PROOF"
    return "E2_R8_CONTROL_NOT_READY"


def run_probe(args):
    receipt=r6.run_probe(args)
    rt=receipt.get("runtime",{})
    receipt["schemaVersion"]=SCHEMA_VERSION
    receipt["experiment"]=EXPERIMENT
    receipt["r6Classification"]=receipt.get("classification")
    receipt["classification"]=classify(rt)
    receipt["controlExchange"]={
        "preStatusExchangeObserved":exchange_present(rt.get("preStatus")),
        "startExchangeObserved":exchange_present(rt.get("start")),
        "postStatusExchangeObserved":exchange_present(rt.get("postStatus")),
        "preStatusMarkers":(rt.get("preStatus") or {}).get("stateMarkers",[]),
        "startMarkers":(rt.get("start") or {}).get("stateMarkers",[]),
        "postStatusMarkers":(rt.get("postStatus") or {}).get("stateMarkers",[]),
        "statusChanged":rt.get("statusChanged"),
        "ctlmgrProcessObserved":rt.get("ctlmgrProcessObserved"),
    }
    receipt.setdefault("safety",{})["controlPayloadPublished"]=False
    receipt["interpretationBoundary"]={
        **receipt.get("interpretationBoundary",{}),
        "genericStateMarkersOnlyWhenPresentInShippedControllerBinary":True,
        "controlPayloadContentNotInterpreted":True,
    }
    return receipt


def parse_args(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--firmware-url");p.add_argument("--expected-size",type=int)
    p.add_argument("--expected-sha256");p.add_argument("--work-dir");p.add_argument("--receipt")
    p.add_argument("--control-wait-seconds",type=float,default=2.0)
    p.add_argument("--verify-seconds",type=float,default=2.0)
    p.add_argument("--sample-interval-seconds",type=float,default=0.05)
    return p.parse_args(argv)


def main(argv=None):
    args=parse_args(argv);rp=pathlib.Path(args.receipt);rp.parent.mkdir(parents=True,exist_ok=True)
    try:data=run_probe(args);rc=0 if data.get("oracleSatisfied") else 2
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
              "error":{"type":type(exc).__name__,"message":str(exc)[:1000]},
              "safety":{"controlPayloadPublished":False,"physicalRouterContact":False,"routerMutationAuthorized":False}}
        rc=3
    rp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc
if __name__=="__main__":raise SystemExit(main())
