#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP, UC_ARM_REG_LR
from wrt3200acm_rehost_core import FirmwareImage,Runner

CMD=0x10000000; STACK=0x10010000; RET=0x10020000
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--elf",required=True); ap.add_argument("--out",required=True); ns=ap.parse_args()
    r=Runner(FirmwareImage(ns.elf)); r.map_scratch(CMD,0x1000); r.map_scratch(STACK,0x1000); r.map_scratch(RET,0x1000)
    # UPDATE_ENCRYPTION action 2 (remove key), enough to prove reusable stop-at-helper/tracing.
    req=bytearray(80); req[0:2]=(0x1122).to_bytes(2,"little"); req[2:4]=(80).to_bytes(2,"little"); req[5]=9; req[8:12]=(2).to_bytes(4,"little")
    r.uc.mem_write(CMD,bytes(req)); r.uc.reg_write(UC_ARM_REG_R0,CMD); r.uc.reg_write(UC_ARM_REG_SP,STACK+0xf00); r.uc.reg_write(UC_ARM_REG_LR,RET)
    result=r.run(0x34d2c,stops=(0x29070,),count=1000)
    report={"schema":"wrt8964-general-rehost-smoke/v1","stop_reason":result["stop_reason"],"instruction_trace_count":len(result["trace"]),"memory_access_count":len(result["memory_accesses"])}
    Path(ns.out).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n"); print(json.dumps(report,indent=2))
    return 0 if report["stop_reason"] and report["stop_reason"]["address"]==0x29070 else 3
if __name__=="__main__": raise SystemExit(main())
