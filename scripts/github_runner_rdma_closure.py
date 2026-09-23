#!/usr/bin/env python3
"""Close the earned GHA RDMA frontier with a deterministic same-host verbs oracle."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import time
from typing import Any

SCHEMA = "github-runner-rdma-closure/v1"
PROBE_VERSION = "public-rdma-verbs-closure/4"

C_SOURCE = r'''
#include <infiniband/verbs.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct endpoint { struct ibv_cq *cq; struct ibv_qp *qp; };

static int gid_is_zero(const union ibv_gid *gid) {
    static const unsigned char zero[16] = {0};
    return memcmp(gid->raw, zero, 16) == 0;
}
static int gid_is_link_local(const union ibv_gid *gid) {
    return gid->raw[0] == 0xfe && gid->raw[1] == 0x80;
}

static int modify_init(struct ibv_qp *qp, uint8_t port) {
    struct ibv_qp_attr a; memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_INIT; a.port_num = port; a.pkey_index = 0;
    a.qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    return ibv_modify_qp(qp, &a,
        IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
}

static int modify_rtr(struct ibv_qp *qp, uint32_t remote_qpn,
                      const struct ibv_port_attr *pa, uint8_t port,
                      int gid_index, const union ibv_gid *gid) {
    struct ibv_qp_attr a; memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_RTR; a.path_mtu = pa->active_mtu;
    a.dest_qp_num = remote_qpn; a.rq_psn = 0;
    a.max_dest_rd_atomic = 1; a.min_rnr_timer = 12;
    a.ah_attr.dlid = pa->lid; a.ah_attr.sl = 0;
    a.ah_attr.src_path_bits = 0; a.ah_attr.port_num = port;
    if (gid_index >= 0 && gid) {
        a.ah_attr.is_global = 1; a.ah_attr.grh.dgid = *gid;
        a.ah_attr.grh.sgid_index = gid_index; a.ah_attr.grh.hop_limit = 1;
    }
    return ibv_modify_qp(qp, &a,
        IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
        IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);
}

static int modify_rts(struct ibv_qp *qp) {
    struct ibv_qp_attr a; memset(&a, 0, sizeof(a));
    a.qp_state = IBV_QPS_RTS; a.timeout = 14; a.retry_cnt = 7;
    a.rnr_retry = 7; a.sq_psn = 0; a.max_rd_atomic = 1;
    return ibv_modify_qp(qp, &a,
        IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);
}

static int poll_one(struct ibv_cq *cq) {
    struct ibv_wc wc; memset(&wc, 0, sizeof(wc));
    for (int i = 0; i < 20000; ++i) {
        int n = ibv_poll_cq(cq, 1, &wc);
        if (n < 0) return -1;
        if (n == 1) return wc.status == IBV_WC_SUCCESS ? 0 : 1000 + (int)wc.status;
        usleep(100);
    }
    return -2;
}

int main(int argc, char **argv) {
    int num = 0, selected = 0, gid_index = -1, stage_rc = 0;
    const char *requested_device = argc > 1 ? argv[1] : NULL;
    int ok_context=0, ok_pd=0, ok_mr=0, ok_cq=0, ok_qp=0;
    int ok_states=0, ok_sendrecv=0, ok_write=0, ok_read=0;
    uint8_t port = 1; const char *stage = "device-list";
    struct ibv_device **list = NULL; struct ibv_context *ctx = NULL;
    struct ibv_pd *pd = NULL; struct endpoint a={0}, b={0};
    struct ibv_mr *mr_send=NULL, *mr_recv=NULL, *mr_read=NULL;
    struct ibv_port_attr pa; struct ibv_device_attr da; union ibv_gid gid;
    uint64_t send_value = UINT64_C(0x1122334455667788), recv_value = 0, read_value = 0;
    memset(&pa,0,sizeof(pa)); memset(&da,0,sizeof(da)); memset(&gid,0,sizeof(gid));

    list=ibv_get_device_list(&num); if(!list || num<1){stage_rc=errno?errno:1;goto out;}
    if(requested_device){
        int found=0;
        for(int i=0;i<num;i++){
            if(strcmp(ibv_get_device_name(list[i]),requested_device)==0){selected=i;found=1;break;}
        }
        if(!found){stage="select-device";stage_rc=6;goto out;}
    }
    stage="open-device"; ctx=ibv_open_device(list[selected]); if(!ctx){stage_rc=errno?errno:1;goto out;} ok_context=1;
    stage="query-device"; if(ibv_query_device(ctx,&da)){stage_rc=errno?errno:1;goto out;}
    stage="query-port"; if(ibv_query_port(ctx,port,&pa)){stage_rc=errno?errno:1;goto out;}
    if(pa.state!=IBV_PORT_ACTIVE){stage_rc=2;goto out;}
    for(int i=0;i<32;i++){ union ibv_gid c; memset(&c,0,sizeof(c));
        if(ibv_query_gid(ctx,port,i,&c)==0 && !gid_is_zero(&c)){
            if(gid_index<0){gid=c;gid_index=i;}
            if(!gid_is_link_local(&c)){gid=c;gid_index=i;break;}
        }}

    stage="alloc-pd"; pd=ibv_alloc_pd(ctx); if(!pd){stage_rc=errno?errno:1;goto out;} ok_pd=1;
    int cq_entries = da.max_cqe >= 4 ? 4 : da.max_cqe;
    if(cq_entries < 1){stage="device-caps";stage_rc=7;goto out;}
    stage="create-cq"; a.cq=ibv_create_cq(ctx,cq_entries,NULL,NULL,0); b.cq=ibv_create_cq(ctx,cq_entries,NULL,NULL,0);
    if(!a.cq||!b.cq){stage_rc=errno?errno:1;goto out;} ok_cq=1;

    int wr = da.max_qp_wr >= 2 ? 2 : da.max_qp_wr;
    int sge = da.max_sge >= 1 ? 1 : da.max_sge;
    if(wr < 1 || sge < 1){stage="device-caps";stage_rc=8;goto out;}
    struct ibv_qp_init_attr qia; memset(&qia,0,sizeof(qia));
    qia.qp_type=IBV_QPT_RC; qia.cap.max_send_wr=wr; qia.cap.max_recv_wr=wr;
    qia.cap.max_send_sge=sge; qia.cap.max_recv_sge=sge;
    stage="create-qp"; qia.send_cq=a.cq; qia.recv_cq=a.cq; a.qp=ibv_create_qp(pd,&qia);
    qia.send_cq=b.cq; qia.recv_cq=b.cq; b.qp=ibv_create_qp(pd,&qia);
    if(!a.qp||!b.qp){stage_rc=errno?errno:1;goto out;} ok_qp=1;

    stage="register-mr";
    mr_send=ibv_reg_mr(pd,&send_value,sizeof(send_value),IBV_ACCESS_LOCAL_WRITE);
    mr_recv=ibv_reg_mr(pd,&recv_value,sizeof(recv_value),
        IBV_ACCESS_LOCAL_WRITE|IBV_ACCESS_REMOTE_WRITE|IBV_ACCESS_REMOTE_READ);
    mr_read=ibv_reg_mr(pd,&read_value,sizeof(read_value),IBV_ACCESS_LOCAL_WRITE);
    if(!mr_send||!mr_recv||!mr_read){stage_rc=errno?errno:1;goto out;} ok_mr=1;

    stage="qp-init"; if(modify_init(a.qp,port)||modify_init(b.qp,port)){stage_rc=errno?errno:1;goto out;}
    stage="qp-rtr";
    if(modify_rtr(a.qp,b.qp->qp_num,&pa,port,gid_index,gid_index>=0?&gid:NULL) ||
       modify_rtr(b.qp,a.qp->qp_num,&pa,port,gid_index,gid_index>=0?&gid:NULL)){
        stage_rc=errno?errno:1;goto out;}
    stage="qp-rts"; if(modify_rts(a.qp)||modify_rts(b.qp)){stage_rc=errno?errno:1;goto out;} ok_states=1;

    stage="send-recv";
    struct ibv_sge rsge={.addr=(uintptr_t)&recv_value,.length=sizeof(recv_value),.lkey=mr_recv->lkey};
    struct ibv_recv_wr rwr,*bad_rwr=NULL; memset(&rwr,0,sizeof(rwr));
    rwr.wr_id=1;rwr.sg_list=&rsge;rwr.num_sge=1;
    if(ibv_post_recv(b.qp,&rwr,&bad_rwr)){stage_rc=errno?errno:1;goto out;}
    struct ibv_sge ssge={.addr=(uintptr_t)&send_value,.length=sizeof(send_value),.lkey=mr_send->lkey};
    struct ibv_send_wr swr,*bad_swr=NULL; memset(&swr,0,sizeof(swr));
    swr.wr_id=2;swr.sg_list=&ssge;swr.num_sge=1;swr.opcode=IBV_WR_SEND;swr.send_flags=IBV_SEND_SIGNALED;
    if(ibv_post_send(a.qp,&swr,&bad_swr)){stage_rc=errno?errno:1;goto out;}
    if((stage_rc=poll_one(a.cq))!=0)goto out; if((stage_rc=poll_one(b.cq))!=0)goto out;
    if(recv_value!=send_value){stage_rc=3;goto out;} ok_sendrecv=1;

    stage="rdma-write"; recv_value=0; memset(&swr,0,sizeof(swr));
    swr.wr_id=3;swr.sg_list=&ssge;swr.num_sge=1;swr.opcode=IBV_WR_RDMA_WRITE;swr.send_flags=IBV_SEND_SIGNALED;
    swr.wr.rdma.remote_addr=(uintptr_t)&recv_value;swr.wr.rdma.rkey=mr_recv->rkey;
    if(ibv_post_send(a.qp,&swr,&bad_swr)){stage_rc=errno?errno:1;goto out;}
    if((stage_rc=poll_one(a.cq))!=0)goto out; if(recv_value!=send_value){stage_rc=4;goto out;} ok_write=1;

    stage="rdma-read"; recv_value=UINT64_C(0x8877665544332211); read_value=0;
    struct ibv_sge readsge={.addr=(uintptr_t)&read_value,.length=sizeof(read_value),.lkey=mr_read->lkey};
    memset(&swr,0,sizeof(swr)); swr.wr_id=4;swr.sg_list=&readsge;swr.num_sge=1;
    swr.opcode=IBV_WR_RDMA_READ;swr.send_flags=IBV_SEND_SIGNALED;
    swr.wr.rdma.remote_addr=(uintptr_t)&recv_value;swr.wr.rdma.rkey=mr_recv->rkey;
    if(ibv_post_send(a.qp,&swr,&bad_swr)){stage_rc=errno?errno:1;goto out;}
    if((stage_rc=poll_one(a.cq))!=0)goto out; if(read_value!=recv_value){stage_rc=5;goto out;} ok_read=1;

    stage="complete"; stage_rc=0;
out:
    printf("{\"device_count\":%d,\"device\":\"%s\",\"port\":%u,\"port_state\":%u,"
           "\"link_layer\":%u,\"gid_index\":%d,\"max_qp_wr\":%d,\"max_sge\":%d,\"max_cqe\":%d,"
           "\"context\":%s,\"pd\":%s,\"mr\":%s,\"cq\":%s,\"qp\":%s,\"qp_states\":%s,"
           "\"send_recv\":%s,\"rdma_write\":%s,\"rdma_read\":%s,\"stage\":\"%s\",\"stage_rc\":%d}\n",
           num,(list&&num>0)?ibv_get_device_name(list[selected]):"",(unsigned)port,(unsigned)pa.state,
           (unsigned)pa.link_layer,gid_index,da.max_qp_wr,da.max_sge,da.max_cqe,
           ok_context?"true":"false",ok_pd?"true":"false",
           ok_mr?"true":"false",ok_cq?"true":"false",ok_qp?"true":"false",ok_states?"true":"false",
           ok_sendrecv?"true":"false",ok_write?"true":"false",ok_read?"true":"false",stage,stage_rc);
    if(mr_read)ibv_dereg_mr(mr_read); if(mr_recv)ibv_dereg_mr(mr_recv); if(mr_send)ibv_dereg_mr(mr_send);
    if(a.qp)ibv_destroy_qp(a.qp); if(b.qp)ibv_destroy_qp(b.qp);
    if(a.cq)ibv_destroy_cq(a.cq); if(b.cq)ibv_destroy_cq(b.cq);
    if(pd)ibv_dealloc_pd(pd); if(ctx)ibv_close_device(ctx); if(list)ibv_free_device_list(list);
    return 0;
}
'''


QP_CENSUS_SOURCE = r'''
#include <infiniband/verbs.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void try_type(struct ibv_pd *pd, struct ibv_cq *cq, enum ibv_qp_type type, const char *name) {
    struct ibv_qp_init_attr qia;
    memset(&qia, 0, sizeof(qia));
    qia.qp_type = type;
    qia.send_cq = cq;
    qia.recv_cq = cq;
    qia.cap.max_send_wr = 1;
    qia.cap.max_recv_wr = 1;
    qia.cap.max_send_sge = 1;
    qia.cap.max_recv_sge = 1;
    errno = 0;
    struct ibv_qp *qp = ibv_create_qp(pd, &qia);
    printf("%s:%s:%d\n", name, qp ? "OK" : "FAIL", qp ? 0 : errno);
    if (qp) ibv_destroy_qp(qp);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int n = 0, selected = -1;
    struct ibv_device **list = ibv_get_device_list(&n);
    if (!list) return 3;
    for (int i = 0; i < n; ++i) {
        if (strcmp(ibv_get_device_name(list[i]), argv[1]) == 0) { selected = i; break; }
    }
    if (selected < 0) { ibv_free_device_list(list); return 4; }
    struct ibv_context *ctx = ibv_open_device(list[selected]);
    if (!ctx) { ibv_free_device_list(list); return 5; }
    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    if (!pd) { ibv_close_device(ctx); ibv_free_device_list(list); return 6; }
    struct ibv_cq *cq = ibv_create_cq(ctx, 4, NULL, NULL, 0);
    if (!cq) { ibv_dealloc_pd(pd); ibv_close_device(ctx); ibv_free_device_list(list); return 7; }

    try_type(pd, cq, IBV_QPT_RC, "RC");
    try_type(pd, cq, IBV_QPT_UC, "UC");
    try_type(pd, cq, IBV_QPT_UD, "UD");
#ifdef IBV_QPT_RAW_PACKET
    try_type(pd, cq, IBV_QPT_RAW_PACKET, "RAW_PACKET");
#endif

    ibv_destroy_cq(cq);
    ibv_dealloc_pd(pd);
    ibv_close_device(ctx);
    ibv_free_device_list(list);
    return 0;
}
'''


def run(argv: list[str], timeout: int = 120, env: dict[str, str] | None = None):
    try:
        cp=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout,env=env)
        return cp.returncode,cp.stdout.strip(),cp.stderr.strip()
    except (OSError,subprocess.SubprocessError) as exc:
        return None,"",f"{type(exc).__name__}: {exc}"

def package_versions() -> dict[str,str]:
    out={}
    for package in ("libibverbs-dev","libibverbs1","ibverbs-providers","ibverbs-utils"):
        code,stdout,_=run(["dpkg-query","-W",package],timeout=15)
        if code==0 and stdout:
            parts=stdout.split()
            out[package]=parts[-1] if len(parts)>1 else stdout
    return out


def rdma_candidates() -> list[dict[str,Any]]:
    root=pathlib.Path("/sys/class/infiniband")
    rows=[]
    if not root.exists(): return rows
    for dev in sorted(root.iterdir()):
        states=[]; nets=[]; uverbs=[]
        ports=dev/"ports"
        if ports.exists():
            for port in sorted(ports.iterdir()):
                try: states.append((port/"state").read_text().strip())
                except OSError: pass
        netroot=dev/"device"/"net"
        if netroot.exists(): nets=[p.name for p in sorted(netroot.iterdir())]
        verbsroot=dev/"device"/"infiniband_verbs"
        if verbsroot.exists(): uverbs=[p.name for p in sorted(verbsroot.iterdir())]
        active=any("ACTIVE" in state for state in states)
        score=(100 if active else 0)+(20 if nets else 0)+(10 if uverbs else 0)+(0 if dev.name.startswith("manae") else 5)
        rows.append({"device":dev.name,"states":states,"netdevs":nets,"uverbs":uverbs,"score":score})
    return sorted(rows,key=lambda x:(x["score"],x["device"]),reverse=True)



def qp_type_census(cc: str, selected: str, root: pathlib.Path) -> dict[str,Any]:
    src=root/"qp_type_census.c"; exe=root/"qp_type_census"
    src.write_text(QP_CENSUS_SOURCE,encoding="utf-8")
    crc,cout,cerr=run([cc,"-O2","-Wall","-Wextra",str(src),"-libverbs","-o",str(exe)],timeout=60)
    if crc!=0:
        return {"classification":"HARNESS_FAILURE","reason":"QP-type census failed to compile",
                "compile_exit":crc,"stderr":cerr[-3000:] or None}
    rc,out,err=run([str(exe),selected],timeout=30)
    rows={}
    for line in out.splitlines():
        parts=line.strip().split(":")
        if len(parts)==3:
            rows[parts[0]]={"created":parts[1]=="OK","errno":int(parts[2]) if parts[2].isdigit() else None}
    return {"classification":"SUPPORTED" if rc==0 else "ORACLE_FAILURE",
            "reason":"QP-type creation census completed" if rc==0 else "QP-type census execution failed",
            "exit_code":rc,"types":rows,"stderr":err[-2000:] or None}


def stock_pingpong(program: str, device: str | None, gid_index: int | None, port: int) -> dict[str,Any]:
    exe=shutil.which(program)
    if not exe or not device:
        return {"classification":"SKIPPED_GUARDRAIL","reason":f"{program} or selected device unavailable"}
    base=[exe,"-d",device,"-i","1","-s","8","-n","4","-p",str(port)]
    if isinstance(gid_index,int) and gid_index>=0:
        base += ["-g",str(gid_index)]
    server=subprocess.Popen(base,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    time.sleep(1)
    client_rc,client_out,client_err=run(base+["127.0.0.1"],timeout=30)
    try:
        server_out,server_err=server.communicate(timeout=30)
        server_rc=server.returncode
    except subprocess.TimeoutExpired:
        server.kill();server_out,server_err=server.communicate();server_rc=None
    passed=(client_rc==0 and server_rc==0)
    return {"classification":"SUPPORTED" if passed else "ORACLE_FAILURE",
            "reason":f"stock {program} same-host exchange passed" if passed else f"stock {program} failed",
            "server_exit":server_rc,"client_exit":client_rc,
            "server_stdout":server_out[-2500:] or None,"server_stderr":server_err[-2500:] or None,
            "client_stdout":client_out[-2500:] or None,"client_stderr":client_err[-2500:] or None,
            "argv":base[1:]}


def pingpong_diagnostic(device: str | None, gid_index: int | None) -> dict[str,Any]:
    exe=shutil.which("ibv_rc_pingpong")
    if not exe or not device:
        return {"classification":"SKIPPED_GUARDRAIL","reason":"ibv_rc_pingpong or selected device unavailable"}
    base=[exe,"-d",device,"-i","1","-s","8","-n","4","-p","19415"]
    if isinstance(gid_index,int) and gid_index>=0: base += ["-g",str(gid_index)]
    server=subprocess.Popen(base,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    time.sleep(1)
    client_rc,client_out,client_err=run(base+["127.0.0.1"],timeout=30)
    try:
        server_out,server_err=server.communicate(timeout=30)
        server_rc=server.returncode
    except subprocess.TimeoutExpired:
        server.kill();server_out,server_err=server.communicate();server_rc=None
    passed=(client_rc==0 and server_rc==0)
    return {"classification":"SUPPORTED" if passed else "ORACLE_FAILURE",
            "reason":"stock ibv_rc_pingpong same-host RC SEND/RECV passed" if passed else "stock ibv_rc_pingpong also failed",
            "server_exit":server_rc,"client_exit":client_rc,
            "server_stdout":server_out[-3000:] or None,"server_stderr":server_err[-3000:] or None,
            "client_stdout":client_out[-3000:] or None,"client_stderr":client_err[-3000:] or None,
            "argv":base[1:]}

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--label",required=True); p.add_argument("--out",required=True)
    args=p.parse_args()
    receipt: dict[str,Any]={
        "schema":SCHEMA,
        "provenance":{"requested_label":args.label,"probe_version":PROBE_VERSION,
            "run_id":os.environ.get("GITHUB_RUN_ID",""),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT",""),
            "workflow_sha":os.environ.get("GITHUB_SHA",""),"image_os":os.environ.get("ImageOS"),
            "image_version":os.environ.get("ImageVersion")},
        "runner":{"system":platform.system(),"machine":platform.machine()},
        "dependency_preparation":{},"oracle":None,"classification":"INCONCLUSIVE","reason":"",
        "warnings":["same-host result does not prove cross-host RDMA reachability",
            "no throughput or latency conclusion is drawn from this functional oracle",
            "ephemerally acquired userspace packages are tooling, not base-image capability evidence"]}

    if platform.system()!="Linux":
        receipt["classification"]="SKIPPED_GUARDRAIL"; receipt["reason"]="RDMA closure is Linux-only"
    elif not pathlib.Path("/dev/infiniband").exists():
        receipt["classification"]="NEGATIVE_OBSERVATION"; receipt["reason"]="/dev/infiniband is absent"
    else:
        candidates=rdma_candidates()
        receipt["device_candidates"]=candidates
        selected=candidates[0]["device"] if candidates else None
        receipt["selected_device"]=selected
        sudo=shutil.which("sudo")
        if not sudo:
            receipt["classification"]="HARNESS_FAILURE"; receipt["reason"]="sudo unavailable for ephemeral dependency preparation"
        else:
            env=dict(os.environ); env["DEBIAN_FRONTEND"]="noninteractive"
            uc,uo,ue=run([sudo,"-n","apt-get","update","-qq"],timeout=180,env=env)
            ic=None;io=ie=""
            if uc==0:
                ic,io,ie=run([sudo,"-n","apt-get","install","-y","-qq","--no-install-recommends",
                    "libibverbs-dev","ibverbs-providers","ibverbs-utils"],timeout=180,env=env)
            receipt["dependency_preparation"]={"apt_update_exit":uc,"apt_install_exit":ic,
                "stderr":(ue+"\n"+ie)[-3000:] or None,"versions":package_versions()}
            if uc!=0 or ic!=0:
                receipt["classification"]="ENVIRONMENT_FAILURE";receipt["reason"]="ephemeral libibverbs tooling preparation failed"
            else:
                cc=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
                if not cc:
                    receipt["classification"]="HARNESS_FAILURE";receipt["reason"]="no C compiler available"
                else:
                    with tempfile.TemporaryDirectory(prefix="rdma-closure-") as td:
                        src=pathlib.Path(td)/"rdma_closure.c";exe=pathlib.Path(td)/"rdma_closure"
                        src.write_text(C_SOURCE,encoding="utf-8")
                        cc_rc,cc_out,cc_err=run([cc,"-O2","-Wall","-Wextra",str(src),"-libverbs","-o",str(exe)],timeout=60)
                        receipt["compile"]={"compiler":cc,"exit_code":cc_rc,"stdout":cc_out[-1500:] or None,"stderr":cc_err[-3000:] or None}
                        if cc_rc!=0:
                            receipt["classification"]="HARNESS_FAILURE";receipt["reason"]="libibverbs oracle failed to compile"
                        else:
                            receipt["qp_type_census"]=qp_type_census(cc,selected,pathlib.Path(td)) if selected else {
                                "classification":"SKIPPED_GUARDRAIL","reason":"no selected RDMA device"}
                            devinfo_rc,devinfo_out,devinfo_err=run(["ibv_devinfo","-d",selected,"-v"],timeout=30) if selected else (None,"","no selected device")
                            receipt["ibv_devinfo"]={"exit_code":devinfo_rc,"stdout":devinfo_out[-6000:] or None,"stderr":devinfo_err[-2000:] or None}
                            rc,stdout,stderr=run([str(exe),selected],timeout=45) if selected else (None,"","no selected device")
                            receipt["execution"]={"exit_code":rc,"stderr":stderr[-3000:] or None}
                            try: oracle=json.loads(stdout.splitlines()[-1]) if stdout else None
                            except (json.JSONDecodeError,IndexError): oracle=None
                            receipt["oracle"]=oracle
                            if isinstance(oracle,dict):
                                gid_index=oracle.get("gid_index")
                                receipt["independent_pingpong"]=pingpong_diagnostic(selected,gid_index)
                                receipt["stock_transport_pingpong"]={
                                    "rc": stock_pingpong("ibv_rc_pingpong",selected,gid_index,19415),
                                    "uc": stock_pingpong("ibv_uc_pingpong",selected,gid_index,19416),
                                    "ud": stock_pingpong("ibv_ud_pingpong",selected,gid_index,19417),
                                }
                            if rc!=0 or not isinstance(oracle,dict):
                                receipt["classification"]="HARNESS_FAILURE";receipt["reason"]="verbs oracle returned no parseable result"
                                receipt["execution"]["stdout"]=stdout[-3000:] or None
                            else:
                                complete=all(bool(oracle.get(k)) for k in ("context","pd","mr","cq","qp","qp_states","send_recv","rdma_write","rdma_read"))
                                if complete:
                                    receipt["classification"]="SUPPORTED"
                                    receipt["reason"]="ordinary-user PD/MR/CQ/RC-QP lifecycle plus SEND/RECV, RDMA WRITE, and RDMA READ all passed deterministic data oracles"
                                else:
                                    receipt["classification"]="ORACLE_FAILURE"
                                    receipt["reason"]=f"full verbs lifecycle stopped at {oracle.get('stage')}"

    path=pathlib.Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(f"RDMA_CLOSURE_RECEIPT={path}");print(json.dumps(receipt,indent=2,sort_keys=True))
    return 0

if __name__=="__main__": raise SystemExit(main())
