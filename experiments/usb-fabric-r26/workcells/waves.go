package main

import (
 "errors"
 "sort"
)

// planWaves deterministically topologically batches truly ready workcells.
// Each wave is independently parallel; stages are sequential only across
// actual dependency edges. Priority is an admission tie-breaker, not a gate.
func planWaves(m Manifest)([][]string,error){
 if err:=validate(m);err!=nil{return nil,err}
 byID:=map[string]Cell{}
 for _,c:=range m.Cells{byID[c.ID]=c}
 done:=map[string]bool{}
 var waves [][]string
 for len(done)<len(byID){
  ready:=[]Cell{}
  for _,c:=range m.Cells{
   if done[c.ID]{continue}
   satisfied:=true
   for _,dep:=range c.Depends{if !done[dep]{satisfied=false;break}}
   if satisfied{ready=append(ready,c)}
  }
  if len(ready)==0{return nil,errors.New("workcell DAG cannot make progress")}
  sort.Slice(ready,func(i,j int)bool{
   if ready[i].Priority!=ready[j].Priority {
    if ready[i].Priority=="P0"{return true}
    if ready[j].Priority=="P0"{return false}
    if ready[i].Priority=="P1"{return true}
    if ready[j].Priority=="P1"{return false}
    return ready[i].Priority<ready[j].Priority
   }
   return ready[i].ID<ready[j].ID
  })
  capN:=m.MaxParallel
  if len(ready)<capN{capN=len(ready)}
  wave:=make([]string,0,capN)
  for _,c:=range ready[:capN]{wave=append(wave,c.ID)}
  for _,id:=range wave{done[id]=true}
  waves=append(waves,wave)
 }
 return waves,nil
}
