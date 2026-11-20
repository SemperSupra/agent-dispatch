package main

import (
 "encoding/json"
 "os"
 "strings"
 "testing"
)
func r27hSnapshot(t *testing.T) Manifest {
 t.Helper()
 raw,err:=os.ReadFile("manifest.json")
 if err!=nil{t.Fatal(err)}
 var m Manifest
 if err=json.Unmarshal(raw,&m);err!=nil{t.Fatal(err)}
 return m
}
func r27hFind(t *testing.T,m *Manifest,id string)*Receipt{
 t.Helper()
 for i:=range m.Receipts {if m.Receipts[i].ID==id{return &m.Receipts[i]}}
 t.Fatalf("missing exact source lineage receipt %s",id)
 return nil
}
func TestR27HActualSnapshotRequiresSecurityCorrectionsAndBlocksRelease(t *testing.T){
 m:=r27hSnapshot(t)
 if r27hFind(t,&m,"r27c-original-go-kernel-stage").RequiresSuccessor!="r27d-current-down-up-security-fix"{
  t.Fatal("R27-C known DOWN splice vulnerability unmarked for security successor")
 }
 if r27hFind(t,&m,"r25a-simulated-qmp-usbip-interlock").RequiresSuccessor!="r25c-event-splice-repaired"{
  t.Fatal("R25-A known UP splice vulnerability unmarked for security successor")
 }
 verdict:=Validate(m)
 if !verdict.Valid||verdict.ReleaseEligible||len(verdict.CriticalRemaining)!=4{
  t.Fatalf("bad security/NO-GO state: %+v",verdict)
 }
 t.Log("R27_H_EXACT_PARENT_SECURITY_CHILD_REQUIRED_AND_PRESENT=PASS")
 t.Log("R27_H_SNAPSHOT_FOUR_P0_GATES_REMAIN_BLOCKED=PASS")
}
func TestR27HMissingWrongOrRedSecuritySuccessorRejected(t *testing.T){
 tests:=[]struct{name string;alter func(*Manifest)}{
  {"missing-child",func(m *Manifest){out:=m.Receipts[:0];for _,r:=range m.Receipts{if r.ID!="r27d-current-down-up-security-fix"{out=append(out,r)}};m.Receipts=out}},
  {"wrong-parent",func(m *Manifest){r27hFind(t,m,"r27d-current-down-up-security-fix").ParentHead="ffffffffffffffffffffffffffffffffffffffff"}},
  {"red-child",func(m *Manifest){r27hFind(t,m,"r27d-current-down-up-security-fix").Outcome="RED"}},
  {"wrong-kind",func(m *Manifest){r27hFind(t,m,"r27d-current-down-up-security-fix").Kind="real-usbip"}},
  {"wrong-domain",func(m *Manifest){r27hFind(t,m,"r27d-current-down-up-security-fix").Domain="qmp-native"}},
  {"missing-r25c",func(m *Manifest){out:=m.Receipts[:0];for _,r:=range m.Receipts{if r.ID!="r25c-event-splice-repaired"{out=append(out,r)}};m.Receipts=out}},
 }
 for _,tc:=range tests{t.Run(tc.name,func(t *testing.T){
  m:=r27hSnapshot(t)
  tc.alter(&m)
  verdict:=Validate(m)
  if verdict.Valid||len(verdict.Errors)==0 {t.Fatalf("security successor misqualification: %+v",verdict)}
 })}
 t.Log("R27_H_MISSING_FALSE_PARENT_RED_CHILD_AND_KIND_INFLATION_REFUSED=PASS")
}
func TestR27HWrongKeyAdmissionCannotPromoteCausalKernelRelease(t *testing.T){
 m:=r27hSnapshot(t)
 for i:=range m.Gates {
  if m.Gates[i].ID=="real_qmp_same_usbip_device_causal_interlock"{
   m.Gates[i].State="PASS"
   m.Gates[i].ReceiptID="r27e-real-linux-vhci-wrong-pin"
  }
 }
 v:=Validate(m)
 if v.Valid||!strings.Contains(strings.Join(v.Errors," | "),"unproved gate PASS"){
  t.Fatalf("wrong-preboot-key kernel admission laundered as full causal handoff: %+v",v)
 }
 t.Log("R27_H_ACTUAL_WRONG_PIN_NEGATIVE_CANNOT_PROMOTE_SAME_CAUSAL_RUN=PASS")
}
