package main

import(
 "context"
 "fmt"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)
func example()Inventory{return Inventory{Repository:"SemperSupra/agent-dispatch",Proofs:[]Evidence{
 {Cell:"R27H14",PR:902,SourceSHA:strings.Repeat("a",40),RunID:101,JobID:201,Conclusion:"success",Disposition:"PASS",Assertion:"R27H14_GUEST_PROOF_REQUIRED_JOURNAL_STILL_HELD=PASS"},
 {Cell:"R27H7",PR:858,SourceSHA:strings.Repeat("b",40),RunID:102,JobID:202,Conclusion:"success",Disposition:"RED",Assertion:"R27H7_SAME_UID_RAW_QMP_DEVICE_ADD_DEL=REPRODUCED"},
}}}
func fake(t *testing.T,inv Inventory,evil string)*httptest.Server{
 t.Helper()
 return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Header.Get("Authorization")!="Bearer fixture"{t.Errorf("no authenticated request: %s",r.URL.Path)}
  var num int
  var p Evidence
  if strings.Contains(r.URL.Path,"/902")||strings.Contains(r.URL.Path,"/101")||strings.Contains(r.URL.Path,"/201"){p=inv.Proofs[0]}else{p=inv.Proofs[1]}
  path:=r.URL.Path
  switch{
  case strings.Contains(path,"/pulls/"):
   fmt.Sscanf(strings.TrimPrefix(path,"/repos/SemperSupra/agent-dispatch/pulls/"),"%d",&num)
   head:=p.SourceSHA;if evil=="wrong-pr"{head=strings.Repeat("0",40)}
   fmt.Fprintf(w,`{"number":%d,"head":{"sha":"%s"}}`,num,head)
  case strings.Contains(path,"/actions/runs/"):
   conclusion:="success";if evil=="run-failed"{conclusion="failure"}
   fmt.Fprintf(w,`{"id":%d,"head_sha":"%s","status":"completed","conclusion":"%s"}`,p.RunID,p.SourceSHA,conclusion)
  case strings.HasSuffix(path,"/logs"):
   marker:=p.Assertion;if evil=="missing-marker"{marker="R27H14_NOT_TESTED"}
   fmt.Fprintln(w,"2026-11-20T00:00:00Z "+marker)
  case strings.Contains(path,"/actions/jobs/"):
   runID:=p.RunID;if evil=="wrong-job-run"{runID=999}
   fmt.Fprintf(w,`{"id":%d,"run_id":%d,"status":"completed","conclusion":"success"}`,p.JobID,runID)
  default:http.Error(w,"not found",404)
  }
 }))
}
func TestFakeGitHubLiveEvidence(t *testing.T){inv:=example();s:=fake(t,inv,"");defer s.Close();if err:=verify(context.Background(),Client{Base:s.URL,Token:"fixture",HTTP:s.Client()},inv);err!=nil{t.Fatal(err)}}
func TestFailClosedLiveVerification(t *testing.T){
 for _,evil:=range []string{"wrong-pr","run-failed","missing-marker","wrong-job-run"}{
  t.Run(evil,func(t *testing.T){inv:=example();s:=fake(t,inv,evil);defer s.Close();if err:=verify(context.Background(),Client{Base:s.URL,Token:"fixture",HTTP:s.Client()},inv);err==nil{t.Fatal("invalid live GitHub evidence admitted")}})
 }
}
func TestMissingSourceRejected(t *testing.T){i:=example();i.Proofs[0].SourceSHA="main";if err:=valid(i);err==nil{t.Fatal("mutable source")}}
func TestHistoricalRedCannotBeRelabeled(t *testing.T){i:=example();i.Proofs[1].Disposition="PASS";if err:=valid(i);err==nil{t.Fatal("RED witness promoted")}}
func TestRequiredSubstringIsNotREDToken(t *testing.T){i:=example();if err:=valid(i);err!=nil{t.Fatal(err)}}
func TestNoMissingOrDuplicateProof(t *testing.T){i:=example();i.Proofs[1].Cell="R27H14";if err:=valid(i);err==nil{t.Fatal("duplicate")}}
func TestLogMarkerRequiresExactToken(t *testing.T){if markerInLog("PREFIX=R27H14_KEY=PASS_suffix","R27H14_KEY=PASS"){t.Fatal("substring witness admitted")};if !markerInLog("2026-11-20T00:00:00Z R27H14_KEY=PASS\n","R27H14_KEY=PASS"){t.Fatal("actual token rejected")}}
func TestUnscopedRunDenied(t *testing.T){i:=example();i.Proofs[0].RunID=0;if valid(i)==nil{t.Fatal("missing run")}}

func TestRejectEchoedButNeverExecutedMarker(t *testing.T){
 log:="2026-11-20T00:00:00Z echo R27H14_GUEST_PROOF_REQUIRED_JOURNAL_STILL_HELD=PASS\n"
 if markerInLog(log,"R27H14_GUEST_PROOF_REQUIRED_JOURNAL_STILL_HELD=PASS"){t.Fatal("shell instruction spoofed completed security assertion")}
}
func TestRejectSubstringStatusSpoof(t *testing.T){
 log:="2026-11-20T00:00:00Z R27H14_KEY=PASS_unfinished\n"
 if markerInLog(log,"R27H14_KEY=PASS"){t.Fatal("trailing suffix spoofed completed status")}
}
func TestRequireJobTimestampPrefix(t *testing.T){
 if markerInLog("R27H14_KEY=PASS\n","R27H14_KEY=PASS"){t.Fatal("untimestamped source string accepted")}
}
