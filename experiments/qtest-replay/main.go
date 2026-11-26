package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"

 experiment "../qtest-contract"
)

// A finite, intentionally small transition model: one initialized legacy
// queue fixture. It does not model USB ownership, concurrency, or DMA.
// The mutant permits a write to an absent queue. Explore the full finite
// phase graph, retain the first violated invariant and its terminal trace.
type state struct { Phase int; Selected, AbsentPFN, PresentPFN, Status uint32 }
type node struct { S state; Trace []string; FirstViolation int }
var labels=[]string{"select-absent","observe-absent","mutate-absent","observe-refused","notify-absent","observe-status","select-present","observe-present","observe-present-pfn"}

func explore(mutant bool)(visited int, terminal node, err error){
 pending:=[]node{{S:state{Status:3},FirstViolation:-1}}
 seen:=map[state]bool{}
 for len(pending)>0 {
  n:=pending[0];pending=pending[1:]
  if seen[n.S]{continue};seen[n.S]=true;visited++
  if n.S.Phase==len(labels){terminal=n;continue}
  s:=n.S
  switch s.Phase {
  case 0:s.Selected=1
  case 2:if s.Selected==1 && mutant{s.AbsentPFN=1}
  case 6:s.Selected=0
  }
  s.Phase++
  v:=n.FirstViolation
  if v<0 && (s.AbsentPFN!=0 || s.PresentPFN!=0 || s.Status!=3){v=s.Phase-1}
  trace:=append(append([]string{},n.Trace...),labels[n.S.Phase])
  pending=append(pending,node{s,trace,v})
 }
 if len(terminal.Trace)!=len(labels){err=errors.New("no terminal trace")}
 return
}

type Plan struct {
 Scope string `json:"scope"`
 SafeStates int `json:"safe_states"`
 MutantStates int `json:"mutant_states"`
 FirstViolation int `json:"first_violation"`
 Trace []string `json:"trace"`
 Proposal json.RawMessage `json:"proposal"`
 Expected []experiment.ExpectedRead `json:"expected"`
}
func plan()(Plan,error){
 a,s,e:=explore(false);if e!=nil || s.FirstViolation!=-1{return Plan{},errors.New("safe model violates invariant")}
 b,m,e:=explore(true);if e!=nil || m.FirstViolation<0{return Plan{},errors.New("mutation survived")}
 p,e:=experiment.TranslateQueueTrace(experiment.QueueTrace{Steps:m.Trace});if e!=nil{return Plan{},e}
 return Plan{"bounded-synthetic-queue-model",a,b,m.FirstViolation,m.Trace,p.Proposal,p.Expected},nil
}
type Receipt struct {
 PlanSHA string `json:"plan_sha256"`
 Vantage string `json:"vantage"`
 Observations []experiment.ExpectedRead `json:"observations"`
 ProcessExit int `json:"process_exit"`
 Cleanup bool `json:"cleanup"`
 ElapsedNS int64 `json:"elapsed_ns"`
}
func hash(b []byte)string{d:=sha256.Sum256(b);return hex.EncodeToString(d[:])}
func verify(p Plan, planBytes []byte, r Receipt)error{
 if r.PlanSHA!=hash(planBytes)||!r.Cleanup||r.ElapsedNS<=0{return errors.New("receipt binding/lifecycle")}
 if (r.Vantage=="qtest"&&r.ProcessExit!=0)||(r.Vantage=="tcg-guest"&&r.ProcessExit!=33)||(r.Vantage!="qtest"&&r.Vantage!="tcg-guest"){return errors.New("vantage/exit mismatch")}
 return experiment.CheckQueueReads(experiment.ReplayPlan{Proposal:p.Proposal,Expected:p.Expected},r.Observations)
}
func run()error{
 p,e:=plan();if e!=nil{return e}
 b,e:=json.Marshal(p);if e!=nil{return e};b=append(b,'\n')
 if len(os.Args)==2&&os.Args[1]=="generate"{_,e=os.Stdout.Write(b);return e}
 if len(os.Args)<4||os.Args[1]!="check"{return errors.New("usage: replay generate | replay check PLAN RECEIPT...")}
 raw,e:=os.ReadFile(os.Args[2]);if e!=nil{return e}
 if string(raw)!=string(b){return errors.New("plan differs from generated model")}
 for _,path:=range os.Args[3:]{
  rb,e:=os.ReadFile(path);if e!=nil{return e};var r Receipt
  if e=json.Unmarshal(rb,&r);e!=nil{return e}
  if e=verify(p,b,r);e!=nil{return fmt.Errorf("%s: %w",path,e)}
  fmt.Printf("VERIFIED %s %s sha256=%s\n",r.Vantage,path,hash(rb))
 }
 return nil
}
func main(){if e:=run();e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}}
