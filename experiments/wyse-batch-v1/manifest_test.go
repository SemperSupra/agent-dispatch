package batchv1
import (
 "encoding/json"
 "strconv"
 "strings"
 "testing"
)
func packet(id string,issue int)Packet{
 return Packet{
  Workcell:id,Issue:issue,Branch:"test/issue-"+strconv.Itoa(issue)+"-"+id,
  AllowedPaths:[]string{"experiments/"+id,".github/workflows/"+id+".yml"},
  SourceSHA:strings.Repeat("a",40),Runner:"ubuntu-24.04",
  Workflow:".github/workflows/"+id+".yml",
  PositiveOracle:"TEST_"+id+"=PASS",
  NegativeOracle:"invalid actor denied",
  CleanupOracle:"SOURCE_AND_LOCAL_ZERO_TAINT=PASS",
  TimeoutMinutes:12,RetryLimit:2,MaxParallel:3,FailFast:false,
  DisposableOCI:true,UsesPhysical:false,WritesProduction:false,
 }
}
func valid()Manifest{
 return Manifest{Schema:1,BatchID:"batch-v1-synthetic",
  Workcells:[]Packet{packet("lane-alpha",801),packet("lane-bravo",802),packet("lane-charlie",803)}}
}
func check(t *testing.T,m Manifest)error{
 t.Helper();b,e:=json.Marshal(m);if e!=nil{t.Fatal(e)}
 _,e=Parse(b);return e
}
func TestValidThreeLanePacket(t *testing.T){
 if e:=check(t,valid());e!=nil{t.Fatal(e)}
 t.Log("BATCH_VALID_THREE_INDEPENDENT_LANES=PASS")
}
func TestScopeCollisionAndDuplicateBranchDenied(t *testing.T){
 m:=valid()
 m.Workcells[1].AllowedPaths[0]="experiments/lane-alpha/file.go"
 if e:=check(t,m);e==nil{t.Fatal("parent path collision accepted")}
 m=valid()
 m.Workcells[1].Branch=m.Workcells[0].Branch
 if e:=check(t,m);e==nil{t.Fatal("duplicate branch allowed")}
 m=valid()
 m.Workcells[1].Issue=m.Workcells[0].Issue
 if e:=check(t,m);e==nil{t.Fatal("duplicate issue allowed")}
 t.Log("BATCH_PATH_AND_BRANCH_COLLISION_DENIAL=PASS")
}
func TestUnsafeHostAndWeakEvidenceDenied(t *testing.T){
 cases:=[]struct{name string;f func(*Manifest)}{
  {"hostInstall",func(m *Manifest){m.Workcells[0].DisposableOCI=false}},
  {"physical",func(m *Manifest){m.Workcells[0].UsesPhysical=true}},
  {"production",func(m *Manifest){m.Workcells[0].WritesProduction=true}},
  {"unsafeRunner",func(m *Manifest){m.Workcells[0].Runner="self-hosted"}},
  {"noOracle",func(m *Manifest){m.Workcells[0].PositiveOracle=""}},
  {"noNegative",func(m *Manifest){m.Workcells[0].NegativeOracle=""}},
  {"noDisposal",func(m *Manifest){m.Workcells[0].CleanupOracle=""}},
  {"missingPin",func(m *Manifest){m.Workcells[0].SourceSHA=""}},
  {"longTimeout",func(m *Manifest){m.Workcells[0].TimeoutMinutes=200}},
  {"failFast",func(m *Manifest){m.Workcells[0].FailFast=true}},
  {"pathEscape",func(m *Manifest){m.Workcells[0].AllowedPaths[0]="../private"}},
  {"hostRoot",func(m *Manifest){m.Workcells[0].AllowedPaths[0]="/etc"}},
  {"wildcard",func(m *Manifest){m.Workcells[0].AllowedPaths[0]="**"}},
 }
 for _,tc:=range cases {
  m:=valid();tc.f(&m)
  if e:=check(t,m);e==nil{t.Fatalf("unsafe packet %s accepted",tc.name)}
 }
 t.Log("BATCH_UNSAFE_OR_INCOMPLETE_PACKETS_DENIED=PASS")
}
