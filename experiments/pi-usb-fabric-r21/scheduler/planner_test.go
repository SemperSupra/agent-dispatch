package batchplanner

import (
 "strings"
 "testing"
)

func fixture() Manifest {
 m:=Manifest{Schema:"usb-fabric.batch.v1",MaxConcurrent:4,MinIndependentActive:3}
 m.ResourcePolicy.PublicActions=true
 m.Workcells=[]Cell{
  {ID:"a",DLE:467,Priority:"P0",Branch:"a",Base:"sha1",Oracle:"prove",WritePrefixes:[]string{"experiments/a/"}},
  {ID:"b",DLE:468,Priority:"P0",Branch:"b",Base:"sha2",Oracle:"prove",WritePrefixes:[]string{"experiments/b/"}},
  {ID:"c",DLE:469,Priority:"P1",Branch:"c",Base:"sha3",Oracle:"prove",WritePrefixes:[]string{"experiments/c/"}},
 }
 return m
}
func TestR21ThreeIndependentTasksAlwaysAdmittedTogether(t *testing.T){
 p,err:=Schedule(fixture(),nil);if err!=nil{t.Fatal(err)}
 if len(p.Admit)!=3||p.Admit[0].ID!="a"||p.Admit[1].ID!="b"||p.Admit[2].ID!="c"||p.Shortfall!=0{t.Fatalf("%+v",p)}
 t.Log("R21_BATCH_THREE_INDEPENDENT_READY_WORKCELLS=PASS")
}
func TestR21BlockedDoesNotSeriallyGateUnrelatedWork(t *testing.T){
 m:=fixture()
 states:=[]Status{{ID:"a",State:"BLOCKED",BlockedReason:"runner unavailable"},{ID:"b",State:"RUNNING"}}
 p,err:=Schedule(m,states);if err!=nil{t.Fatal(err)}
 if len(p.Admit)!=1||p.Admit[0].ID!="c"||len(p.Running)!=1||p.Shortfall!=1{t.Fatalf("%+v",p)}
 t.Log("R21_BATCH_P0_BLOCKER_NEVER_STOPS_INDEPENDENT_P1=PASS")
}
func TestR21NeverReplaysREDOrCompletedWorkWithoutEvidence(t *testing.T){
 m:=fixture()
 states:=[]Status{{ID:"a",State:"RED"},{ID:"b",State:"QUALIFIED_TEST_ONLY"}}
 p,err:=Schedule(m,states);if err!=nil{t.Fatal(err)}
 if len(p.Admit)!=1||p.Admit[0].ID!="c"||len(p.Blocked)!=1{t.Fatalf("%+v",p)}
 t.Log("R21_BATCH_RED_NOT_AUTO_RETRIED=PASS")
}
func TestR21OverlapAndEscapesFailClosed(t *testing.T){
 tests:=[]struct{name,path string}{
  {"prefix-nesting","experiments/a/child/"},
  {"traversal","../.github/"},
  {"git-dir",".git/config"},
 }
 for _,tc:=range tests {
  t.Run(tc.name,func(t *testing.T){
   m:=fixture();m.Workcells[1].WritePrefixes=[]string{tc.path}
   if err:=Validate(m);err==nil{t.Fatal("unsafe scope accepted")}
  })
 }
 m:=fixture();m.Workcells[1].WritePrefixes=[]string{"experiments/a"}
 if err:=Validate(m);err==nil||!strings.Contains(err.Error(),"overlap"){t.Fatalf("missing prefix overlap check: %v",err)}
 t.Log("R21_BATCH_PATH_ESCAPE_AND_NESTED_OWNERSHIP_DENIED=PASS")
}
func TestR21UnsupportedStatesAndResourceViolationsRefuse(t *testing.T){
 m:=fixture();m.ResourcePolicy.PaidPrivate=true
 if _,err:=Schedule(m,nil);err==nil{t.Fatal("paid private Actions admitted")}
 m=fixture();if _,err:=Schedule(m,[]Status{{ID:"a",State:"BLOCKED"}});err==nil{t.Fatal("missing blocker reason admitted")}
 m=fixture();if _,err:=Schedule(m,[]Status{{ID:"a",State:"QUALIFIED"}});err==nil{t.Fatal("unrecognized state admitted")}
 m=fixture();if _,err:=Schedule(m,[]Status{{ID:"a",State:"RUNNING"},{ID:"a",State:"RUNNING"}});err==nil{t.Fatal("duplicate status admitted")}
 t.Log("R21_BATCH_RESOURCE_AND_STATE_REFUSALS=PASS")
}
