package experiment
import ("testing";"strings")

func TestReceipt(t *testing.T) {
 proposal:=[]byte(`{"version":"v1","scope":"synthetic-device-model","operations":[{"kind":"clock-step","nanoseconds":1}]}`)
 evidence:=[]byte("synthetic example evidence")
 zero,one:=0,1
 good:=Receipt{Scope:"synthetic-device-model",SourceCommit:strings.Repeat("a",40),ProposalSHA256:digest(proposal),EvidenceSHA256:digest(evidence),Status:"PASS",ExitCode:&zero,Planned:1,Exercised:1,Cleanup:true}
 if err:=VerifyReceipt(good,proposal,evidence);err!=nil{t.Fatal(err)}
 for _,c:=range []struct{name string;mutate func(*Receipt)}{
  {"no-exit",func(r *Receipt){r.ExitCode=nil}},
  {"bad-exit",func(r *Receipt){r.ExitCode=&one}},
  {"no-cleanup",func(r *Receipt){r.Cleanup=false}},
  {"skipped",func(r *Receipt){r.Exercised=0;r.Skipped=1}},
  {"failure",func(r *Receipt){r.Failed=1}},
  {"not-exercised",func(r *Receipt){r.Exercised=0}},
  {"live-promotion",func(r *Receipt){r.Scope="live"}},
  {"bad-source",func(r *Receipt){r.SourceCommit="main"}},
  {"wrong-proposal",func(r *Receipt){r.ProposalSHA256=strings.Repeat("0",64)}},
  {"wrong-evidence",func(r *Receipt){r.EvidenceSHA256=strings.Repeat("0",64)}},
  {"overcount",func(r *Receipt){r.Exercised=2}},
  {"not-run-contradiction",func(r *Receipt){r.Status="NOT_RUN"}},
  {"fail-zero",func(r *Receipt){r.Status="FAIL"}},
 }{t.Run(c.name,func(t *testing.T){r:=good;c.mutate(&r);if VerifyReceipt(r,proposal,evidence)==nil{t.Fatal("contradictory receipt admitted")}})}
 if VerifyReceipt(good,proposal,[]byte("changed"))==nil{t.Fatal("tampering admitted")}
 failed:=good;failed.Status="FAIL";failed.ExitCode=&one;failed.Failed=1
 if err:=VerifyReceipt(failed,proposal,evidence);err!=nil{t.Fatal("failure must be recordable",err)}
 notRun:=good;notRun.Status="NOT_RUN";notRun.Exercised=0;notRun.ExitCode=nil
 if err:=VerifyReceipt(notRun,proposal,evidence);err!=nil{t.Fatal("nonexecution must be recordable",err)}
}
