package main

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestEachFrozenArmManifestContainsOnlyItsOwnSearchPlan(t *testing.T) {
 for _,arm:=range []string{"reference","cpe"} {
  t.Run(arm,func(t *testing.T){
   src:=filepath.Join("..","..","pilot","arms",arm,"plan.json")
   var input ArmPlan
   raw,err:=readJSON(src,&input);if err!=nil{t.Fatal(err)}
   if err:=validateArm(input);err!=nil{t.Fatal(err)}
   if input.Arm!=arm||len(input.Queries)!=3||input.ScienceClass!="SYNTHETIC_TRANSPORT_ONLY"{t.Fatalf("mismatched %s",arm)}
   if input.QueryAuthorityRef!="SYNTHETIC_TEST_ONLY_NOT_CPE_AUTHORITY"{t.Fatal("bogus authority")}
   if strings.Contains(string(raw),"reference_queries")||strings.Contains(string(raw),"cpe_projection_sha256"){t.Fatal("two-arm input leak")}
  })
 }
}
func TestSeparateJobsEachIssueOnlyTheirThreeQueries(t *testing.T){
 queryCounts:=map[string]int{}
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  queryCounts[r.URL.Query().Get("q")]++
  w.Header().Set("Content-Type","application/json")
  _,_=w.Write([]byte(`{"results":[]}`))
 }))
 defer server.Close()
 for _,arm:=range []string{"reference","cpe"}{
  path:=filepath.Join("..","..","pilot","arms",arm,"plan.json")
  got,err:=runArmFile(context.Background(),path,server.URL,server.Client())
  if err!=nil{t.Fatal(err)}
  if got.Arm!=arm||got.Attempted!=3||got.Succeeded!=3||got.Failed!=0{t.Fatalf("%s incorrect %+v",arm,got)}
  if len(got.Attempts)!=3{t.Fatal("wrong per-arm count")}
  for _,a:=range got.Attempts {if a.Track!=arm{t.Fatal("cross-arm result contamination")}}
 }
 if len(queryCounts)!=6{t.Fatalf("unexpected duplicate or missing queries: %+v",queryCounts)}
}
func TestCannotClaimRealCPEByChangingArmPlanLabel(t *testing.T){
 path:=filepath.Join("..","..","pilot","arms","cpe","plan.json")
 var p ArmPlan
 _,err:=readJSON(path,&p);if err!=nil{t.Fatal(err)}
 p.ScienceClass="PAIRED_BLIND_PASS"
 if validateArm(p)==nil{t.Fatal("unearned science allowed")}
 p.ScienceClass="SYNTHETIC_TRANSPORT_ONLY"
 p.QueryAuthorityRef="real-private-cpe"
 if validateArm(p)==nil{t.Fatal("unverified CPE claim allowed")}
 p.QueryAuthorityRef="SYNTHETIC_TEST_ONLY_NOT_CPE_AUTHORITY"
 p.DataClass="private"
 if validateArm(p)==nil{t.Fatal("private data projected to public")}
 p.DataClass="public-reviewed";p.Arm="both"
 if validateArm(p)==nil{t.Fatal("combined arm accepted")}
}
func TestArmFailureMustRemainFailureAndContainNoInventedEvidence(t *testing.T){
 var p ArmPlan
 b,err:=os.ReadFile(filepath.Join("..","..","pilot","arms","reference","plan.json"));if err!=nil{t.Fatal(err)}
 if err:=json.Unmarshal(b,&p);err!=nil{t.Fatal(err)}
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.WriteHeader(200)
  _,_=w.Write([]byte(`{"error":"upstream blocked"}`))
 }))
 defer server.Close()
 result,err:=runArm(context.Background(),p,b,server.URL,server.Client())
 if err!=nil{t.Fatal(err)}
 if result.TerminalState!="SOURCE_EXECUTOR_GAP"||result.Failed!=3||result.Succeeded!=0{t.Fatalf("fabricated success %+v",result)}
 for _,attempt:=range result.Attempts {if len(attempt.Hits)!=0{t.Fatal("fabricated evidence")}}
}
