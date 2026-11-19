package batchplanner

import (
 "strings"
 "testing"
)
func validReceipt() (Manifest,map[string]string,Receipt){
 m:=fixture();sha:=strings.Repeat("a",40)
 heads:=map[string]string{"a":sha}
 r:=Receipt{ID:"a",DLE:467,Branch:"a",HeadSHA:sha,RunID:1001,JobIDs:[]int64{2002},
  State:"QUALIFIED_TEST_ONLY",Assertions:map[string]string{"R21_LIVE_TEST":"PASS","REAL_GUEST_ATTESTATION":"NOT_TESTED"},
  Limitations:[]string{"public TEST-ONLY signer; production guest identity absent"},
 }
 return m,heads,r
}
func TestR21EvidenceReceiptsNeedSourceJobsLimitationsAndOriginalRED(t *testing.T){
 m,heads,r:=validReceipt()
 if err:=CheckReceipts(m,heads,[]Receipt{r});err!=nil{t.Fatal(err)}
 wrong:=r;wrong.HeadSHA=strings.Repeat("b",40)
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("stale head qualified")}
 wrong=r;wrong.JobIDs=nil
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("run without jobs qualified")}
 wrong=r;wrong.Assertions=map[string]string{"R21_LIVE_TEST":"PASS"}
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("no NOT_TESTED boundary qualified")}
 wrong=r;wrong.Limitations=nil
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("unbounded trust claim qualified")}
 wrong=r;wrong.State="QUALIFIED_PRODUCTION"
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("production bypass admitted")}
 wrong=r;wrong.State="RED";wrong.Assertions=map[string]string{"BROKER_RESTART":"RED"};wrong.FailureReason=""
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("original RED without failure reason accepted")}
 wrong.FailureReason="GitHub job returned nonzero: missing journal"
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err!=nil{t.Fatal(err)}
 t.Log("R21_BATCH_TEST_ONLY_EVIDENCE_HEAD_JOB_BOUNDARIES=PASS")
 t.Log("R21_BATCH_RED_FAILURE_NEVER_ERASED=PASS")
}
func TestR21DuplicateAndUnknownActorReceiptsDenied(t *testing.T){
 m,heads,r:=validReceipt()
 if err:=CheckReceipts(m,heads,[]Receipt{r,r});err==nil{t.Fatal("duplicate receipt admitted")}
 wrong:=r;wrong.ID="unknown"
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("unknown actor admitted")}
 wrong=r;wrong.DLE=999
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("DLE ownership violation admitted")}
 wrong=r;wrong.Branch="b"
 if err:=CheckReceipts(m,heads,[]Receipt{wrong});err==nil{t.Fatal("cross-branch ownership admitted")}
 t.Log("R21_BATCH_CROSS_WORKCELL_EVIDENCE_LAUNDERING_DENIED=PASS")
}
