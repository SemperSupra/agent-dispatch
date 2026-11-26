package main

import (
 "bytes"
 "encoding/json"
 "testing"
)

func fixture(order string) Receipt {
 raw:=[]byte("synthetic log")
 r:=Receipt{Schedule:order,Present:p,Absent:a,Status:3,ResetPresent:p,Cleanup:true,ElapsedNS:1,RawSHA256:digest(raw)}
 if order=="ABAB"||order=="ABBA"{r.Present=w}
 prior:=p; counts:=map[byte]int{}
 for i,actor:=range []byte(order){
  action:="select";if counts[actor]>0{if actor=='A'{action="write"}else{action="read"}}
  counts[actor]++;after:=oracle[order][i]
  r.Steps=append(r.Steps,Step{string(actor),action,prior,after});prior=after
 }
 return r
}
func TestSixSchedules(t *testing.T){
 for _,order:=range orders{t.Run(order,func(t *testing.T){
  r:=fixture(order);b,_:=json.Marshal(r);decoded,e:=decode(append(b,'\n'))
  if e!=nil{t.Fatal(e)}
  if e=check(decoded,order,[]byte("synthetic log"));e!=nil{t.Fatal(e)}
 })}
}
func TestRefuse(t *testing.T){
 for _,c:=range []struct{name string;mutate func(*Receipt)}{
  {"wrong-target",func(r *Receipt){r.Steps[2].Before=a}},
  {"wrong-write",func(r *Receipt){r.Steps[2].After=p}},
  {"wrong-read",func(r *Receipt){r.Steps[3].After=p}},
  {"wrong-order",func(r *Receipt){r.Schedule="AABB"}},
  {"absent-mutation",func(r *Receipt){r.Absent[2]=1}},
  {"wrong-reset",func(r *Receipt){r.ResetPresent=w}},
  {"unclean-exit",func(r *Receipt){r.ProcessExit=1}},
  {"cleanup-missing",func(r *Receipt){r.Cleanup=false}},
  {"invalid-time",func(r *Receipt){r.ElapsedNS=0}},
  {"digest-mismatch",func(r *Receipt){r.RawSHA256=digest([]byte("other"))}},
 }{t.Run(c.name,func(t *testing.T){
  r:=fixture("ABAB");c.mutate(&r);if check(r,"ABAB",[]byte("synthetic log"))==nil{t.Fatal("accepted")}
 })}
 r:=fixture("ABAB");b,_:=json.Marshal(r);b=append(b,'\n')
 for _,c:=range []struct{name,old,new string}{
  {"duplicate",`"process_exit":0`,`"process_exit":0,"process_exit":0`},
  {"case",`"process_exit":0`,`"Process_exit":0`},
  {"null",`"process_exit":0`,`"process_exit":null`},
  {"missing",`"process_exit":0,`,``},
  {"unknown",`"process_exit":0`,`"process_exit":0,"grant":true`},
  {"short-array",`"present":[0,256,1]`,`"present":[0,256]`},
 }{t.Run(c.name,func(t *testing.T){
  bad:=bytes.Replace(b,[]byte(c.old),[]byte(c.new),1)
  if bytes.Equal(b,bad){t.Fatal("ineffective mutation")}
  if _,e:=decode(bad);e==nil{t.Fatal("accepted")}
 })}
}
