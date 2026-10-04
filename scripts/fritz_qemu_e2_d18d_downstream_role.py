#!/usr/bin/env python3
"""E2-D18d: reconcile D17/D18c observation role with accepted libsvctl topology."""
from __future__ import annotations
import argparse, importlib.util, json, pathlib

_D14=pathlib.Path(__file__).with_name("fritz_qemu_e2_d14_libsvctl_liveness.py")
_spec=importlib.util.spec_from_file_location("d14",_D14)
if _spec is None or _spec.loader is None: raise RuntimeError("unable to load D14")
d14=importlib.util.module_from_spec(_spec); _spec.loader.exec_module(d14)

SCHEMA_VERSION=1
EXPERIMENT="fritz-qemu-e2-d18d-downstream-role/v1"

def reconcile(d14_receipt: dict) -> dict:
    edges={(e["source"],e["target"]) for e in d14_receipt["library"]["combinedAcceptedCallEdges"]}
    init_chain = ("_svctl_init","_svctl_send") in edges and ("_svctl_send","send") in edges
    pkt_chain = ("_svctl_send_pkt","_svctl_send") in edges and ("_svctl_send","send") in edges
    downstream = init_chain and pkt_chain
    return {
        "schemaVersion":SCHEMA_VERSION,
        "experiment":EXPERIMENT,
        "classification":"E2_D18D_DOWNSTREAM_SEND_ROLE_EARNED" if downstream else "E2_D18D_DOWNSTREAM_ROLE_NOT_EARNED",
        "oracleSatisfied":bool(d14_receipt.get("oracleSatisfied") and downstream),
        "target":d14_receipt["target"],
        "reconciliation":{
            "d18ObservationRole":"caller_pic_callsite_before_callee_entry",
            "d18FunctionEntryClaimAccepted":False,
            "initToSendChainAccepted":init_chain,
            "sendPktToSendChainAccepted":pkt_chain,
            "sharedDownstreamRole":"_svctl_send entry / send-boundary argument role" if downstream else None,
            "downstreamObservationPointMechanicallyEarned":downstream,
        },
        "interpretationBoundary":{
            "newRuntimeObservationPerformed":False,
            "newOffsetsOrDigestWindowsInvented":False,
            "protocolEnumValuesAccepted":False,
            "packetFieldLayoutAccepted":False,
            "staticTopologyIsNotRuntimeVerbDiscrimination":True,
        },
        "safety":{
            "physicalRouterContact":False,
            "routerMutationAuthorized":False,
            "wirePayloadPublished":False,
            "rawDisassemblyPublished":False,
            "instructionAddressesPublished":False,
        },
    }

def parse_args(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--firmware-url",required=True); p.add_argument("--expected-size",type=int,required=True)
    p.add_argument("--expected-sha256",required=True); p.add_argument("--objdump",default="mips-linux-gnu-objdump")
    p.add_argument("--work-dir",required=True); p.add_argument("--receipt",required=True)
    return p.parse_args(argv)

def main(argv=None):
    args=parse_args(argv); out=pathlib.Path(args.receipt); out.parent.mkdir(parents=True,exist_ok=True)
    try:
        base=d14.run_probe(args)
        data=reconcile(base)
        rc=0 if data["oracleSatisfied"] else 2
    except Exception as exc:
        data={"schemaVersion":SCHEMA_VERSION,"experiment":EXPERIMENT,"classification":"HARNESS_FAILURE","oracleSatisfied":False,
              "error":{"type":type(exc).__name__,"message":str(exc)[:1000]}}
        rc=3
    out.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"classification":data["classification"],"oracleSatisfied":data["oracleSatisfied"]},sort_keys=True))
    return rc
if __name__=="__main__": raise SystemExit(main())
