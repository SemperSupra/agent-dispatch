package experiment

import (
 "bytes"
 "encoding/json"
 "fmt"
)

// QueueTrace is a deliberately narrow counterexample vocabulary for an already
// initialized synthetic legacy VirtIO fixture. It does not accept arbitrary
// addresses, execute operations, or establish device or runtime authority.
type QueueTrace struct {
 Steps []string
}
type ExpectedRead struct {
 OperationIndex int `json:"operation_index"`
 Value uint32 `json:"value"`
}
type ReplayPlan struct {
 Proposal []byte
 Expected []ExpectedRead
}

// TranslateQueueTrace accepts a single supported causal chain, with explicit
// read oracles. Unsupported or incomplete traces fail closed, not approximated.
// The fixture must independently establish BAR0=0x1000, queue0 size=256,
// status=3, no programmed queue addresses, and fresh process identity.
func TranslateQueueTrace(trace QueueTrace) (ReplayPlan,error) {
 var result ReplayPlan
 expected:=[]string{"select-absent","observe-absent","mutate-absent","observe-refused","notify-absent","observe-status","select-present","observe-present","observe-present-pfn"}
 if len(trace.Steps)!=len(expected){return result,fmt.Errorf("incomplete or extended trace")}
 for i,k:=range expected {if trace.Steps[i]!=k{return result,fmt.Errorf("unsupported step %d",i)}}
 ptr:=func(x uint32)*uint32{return &x}
 w:=func(p,n,v uint32)Operation{return Operation{Kind:"pio-write",Port:ptr(p),Width:ptr(n),Value:ptr(v)}}
 r:=func(p,n uint32)Operation{return Operation{Kind:"pio-read",Port:ptr(p),Width:ptr(n)}}
 e:=Experiment{Version:"v1",Scope:"synthetic-device-model",Operations:[]Operation{
 w(0x100e,2,1),r(0x100c,2),w(0x1008,4,1),r(0x1008,4),
 w(0x1010,2,1),r(0x1012,1),w(0x100e,2,0),r(0x100c,2),r(0x1008,4),
 }}
 data,err:=json.Marshal(e);if err!=nil{return result,err}
 if _,err=Decode(bytes.NewReader(data));err!=nil{return result,err}
 return ReplayPlan{Proposal:data,Expected:[]ExpectedRead{{1,0},{3,0},{5,3},{7,256},{8,0}}},nil
}

// CheckQueueReads compares the exact observed sequence, never a self-declared
// PASS. The caller must separately establish provenance and receipt integrity.
func CheckQueueReads(plan ReplayPlan, actual []ExpectedRead) error {
 if len(plan.Expected)==0 || len(actual)!=len(plan.Expected){return fmt.Errorf("missing or extra observations")}
 for i,want:=range plan.Expected {if actual[i]!=want{return fmt.Errorf("observation %d differs: want %+v got %+v",i,want,actual[i])}}
 return nil
}
