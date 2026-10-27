package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func mockRun(id int64, status, conclusion string) APIRun{
 r:=APIRun{
  ID:id,Name:"comment-wake:123",Path:workflow,Event:"issue_comment",Status:status,
  HeadSHA:strings.Repeat("a",40),RunAttempt:1,URL:"https://github.com/SemperSupra/agent-dispatch/actions/runs/40448376152",
  Repository:APIRepository{FullName:repo},
 }
 if conclusion!=""{r.Conclusion=&conclusion}
 return r
}
func serverRun(t *testing.T,x APIRun)*httptest.Server {
 t.Helper()
 return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET"||r.URL.Path!="/40448376152"{t.Fatalf("unexpected request %s",r.URL)}
  _=json.NewEncoder(w).Encode(x)
 }))
}
func TestObserveNativeSuccessDoesNotBecomeScientificSuccess(t *testing.T){
 s:=serverRun(t,mockRun(40448376152,"completed","success"));defer s.Close()
 x,e:=observe(context.Background(),s.Client(),s.URL+"/","40448376152")
 if e!=nil{t.Fatal(e)}
 if x.ControlState!="EXECUTOR_COMPLETE_EVIDENCE_NOT_VALIDATED"||
 x.ScienceState!="UNJUDGED_NEEDS_TRUSTED_PRIVATE_INGEST"{t.Fatalf("overstated success: %+v",x)}
 if x.RunID!=40448376152{t.Fatal(x)}
}
func TestObserveRunStateAndCancellation(t *testing.T){
 for _,v:=range []struct{status,conclusion,want string}{
 {"queued","","OBSERVING_NATIVE"},
 {"in_progress","","OBSERVING_NATIVE"},
 {"completed","cancelled","CANCELLED_NATIVE"},
 {"completed","failure","FAILED_NATIVE"},
 {"completed","skipped","NOT_ADMITTED_OR_SKIPPED"},
 }{
  s:=serverRun(t,mockRun(40448376152,v.status,v.conclusion))
  x,e:=observe(context.Background(),s.Client(),s.URL+"/","40448376152")
  s.Close()
  if e!=nil||x.ControlState!=v.want{t.Fatalf("state %+v error %v",x,e)}
 }
}
func TestWrongWorkflowOrSourceCannotBeObservedAsMCPGHA(t *testing.T){
 for _,mutate:=range []func(*APIRun){
  func(x *APIRun){x.Path=".github/workflows/unrelated.yml"},
  func(x *APIRun){x.Repository.FullName="unrelated/public"},
  func(x *APIRun){x.ID=1},
  func(x *APIRun){x.HeadSHA="not-a-sha"},
  func(x *APIRun){x.RunAttempt=0},
  func(x *APIRun){x.Status="magical-complete"},
 }{
  x:=mockRun(40448376152,"completed","success");mutate(&x)
  s:=serverRun(t,x)
  _,e:=observe(context.Background(),s.Client(),s.URL+"/","40448376152")
  s.Close()
  if e==nil{t.Fatalf("accepted foreign/unbound Actions evidence: %+v",x)}
 }
 for _,id:=range []string{"","0","-1","1/../../secrets","123abc","123?evil"}{
  _,e:=observe(context.Background(),&http.Client{},"http://127.0.0.1/ ",id)
  if e==nil{t.Fatalf("accepted invalid run ID %q",id)}
 }
}
func TestReceiptHashVerificationNeverClaimsDecryption(t *testing.T){
 tmp:=t.TempDir()
 b:=[]byte("synthetic ciphertext bytes not decryptable")
 h:=sha256.Sum256(b);sha:=hex.EncodeToString(h[:])
 cipher:=filepath.Join(tmp,"result.age")
 if e:=os.WriteFile(cipher,b,0600);e!=nil{t.Fatal(e)}
 r:=Receipt{Schema:"mcp-gha-sealed-transport-canary/v1",
  ScienceValid:false,TreatmentAuthenticity:"SYNTHETIC_TEST_ONLY_NOT_CPE_AUTHORITY",
  PublicRunID:"40448376152",PublicRunAttempt:"1",SourceSHA:strings.Repeat("a",40),
  PlanSHA256:strings.Repeat("b",64),ProjectionSHA256:strings.Repeat("c",64),
  SearxngConfigSHA256:strings.Repeat("d",64),SearxngImageDigest:"pinned",
  TerminalState:"RETRIEVAL_PASS",Attempted:6,Succeeded:6,Failed:0,
  CiphertextSHA256:sha,CiphertextBytes:int64(len(b))}
 receipt:=filepath.Join(tmp,"receipt.json")
 write:=func(v Receipt){t.Helper();d,e:=json.Marshal(v);if e!=nil{t.Fatal(e)};if e:=os.WriteFile(receipt,d,0600);e!=nil{t.Fatal(e)}}
 write(r)
 v,e:=verify(receipt,cipher)
 if e!=nil{t.Fatal(e)}
 if !v.CiphertextVerified||v.ScienceState!="SYNTHETIC_ONLY_NO_CPE_AUTHORITY_OR_ADJUDICATION"||
 v.ArtifactState!="CIPHERTEXT_DIGEST_MATCH_ONLY_NOT_DECRYPTED"{t.Fatalf("false scientific assurance: %+v",v)}
 r.ScienceValid=true;write(r)
 if _,e:=verify(receipt,cipher);e==nil{t.Fatal("bogus science_valid accepted")}
 r.ScienceValid=false;r.CiphertextSHA256=strings.Repeat("f",64);write(r)
 if _,e:=verify(receipt,cipher);e==nil{t.Fatal("bad ciphertext digest accepted")}
}
func TestDiscoveryThreeAudiences(t *testing.T){
 d:=describe()
 a:=d["audiences"].([]string)
 if len(a)!=3||a[0]!="human"||a[1]!="automation"||a[2]!="agent"{t.Fatal(a)}
 s,_:=json.Marshal(d)
 for _,item:=range []string{"cancel","mcp gha start smoke","mcp gha sweep pilot","UNJUDGED"}{
  if !strings.Contains(string(s),item){t.Errorf("missing user-visible capability %q",item)}
 }
}
