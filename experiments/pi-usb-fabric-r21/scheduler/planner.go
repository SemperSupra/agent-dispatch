// Package batchplanner is a deterministic, offline planner for weak-model
// workcells. It never dispatches jobs or marks CI qualified by itself.
package batchplanner

import (
 "errors"
 "fmt"
 "path"
 "sort"
 "strings"
)

type Manifest struct {
 Schema string `json:"schema"`
 MaxConcurrent int `json:"max_concurrent"`
 MinIndependentActive int `json:"min_independent_active"`
 ResourcePolicy struct {
  PublicActions bool `json:"public_github_actions"`
  PaidPrivate bool `json:"private_paid_minutes"`
  AutoMerge bool `json:"auto_merge"`
  Production bool `json:"production"`
  Secrets bool `json:"secrets"`
 } `json:"resource_policy"`
 Workcells []Cell `json:"workcells"`
}
type Cell struct {
 ID string `json:"id"`
 DLE int `json:"dle"`
 Priority string `json:"priority"`
 Branch string `json:"branch"`
 Base string `json:"base"`
 Oracle string `json:"oracle"`
 WritePrefixes []string `json:"write_prefixes"`
}
type Status struct {
 ID string `json:"id"`
 State string `json:"state"`
 BlockedReason string `json:"blocked_reason,omitempty"`
}
type Plan struct {
 Admit []Cell `json:"admit"`
 Running []string `json:"running"`
 Blocked []Status `json:"blocked"`
 Shortfall int `json:"shortfall"`
 NotReadyReason string `json:"not_ready_reason,omitempty"`
}
func cleanPrefix(raw string)(string,error){
 if raw=="" || strings.HasPrefix(raw,"/") || strings.Contains(raw,"\\") {return "",fmt.Errorf("invalid write prefix %q",raw)}
 p:=path.Clean(raw)
 if p=="." || p==".." || strings.HasPrefix(p,"../") || strings.HasPrefix(p,".git/") || p==".git"{return "",fmt.Errorf("unsafe write prefix %q",raw)}
 if strings.HasSuffix(raw,"/") {p+="/"}
 return p,nil
}
func overlaps(a,b string)bool{
 a0:=strings.TrimSuffix(a,"/");b0:=strings.TrimSuffix(b,"/")
 return a0==b0 || strings.HasPrefix(a0,b0+"/") || strings.HasPrefix(b0,a0+"/")
}
func Validate(m Manifest)error{
 if m.Schema!="usb-fabric.batch.v1" || m.MinIndependentActive<1 || m.MaxConcurrent<m.MinIndependentActive || m.MaxConcurrent>16{return errors.New("invalid bounded batch contract")}
 if !m.ResourcePolicy.PublicActions || m.ResourcePolicy.PaidPrivate || m.ResourcePolicy.AutoMerge || m.ResourcePolicy.Production || m.ResourcePolicy.Secrets{return errors.New("disallowed free-tier resource policy")}
 if len(m.Workcells)<m.MinIndependentActive{return errors.New("insufficient independent workcells")}
 ids:=map[string]bool{}; branches:=map[string]bool{}; dles:=map[int]bool{}
 type entry struct{owner,prefix string}
 var all []entry
 for _,c:=range m.Workcells {
  if c.ID=="" || c.DLE<=0 || c.Branch=="" || c.Base=="" || c.Oracle=="" || (c.Priority!="P0" && c.Priority!="P1"){return fmt.Errorf("incomplete workcell %q",c.ID)}
  if ids[c.ID]||branches[c.Branch]||dles[c.DLE]{return fmt.Errorf("duplicate workcell owner %q",c.ID)}
  ids[c.ID]=true;branches[c.Branch]=true;dles[c.DLE]=true
  if len(c.WritePrefixes)==0{return fmt.Errorf("missing write scope %s",c.ID)}
  for _,p:=range c.WritePrefixes {
   canon,err:=cleanPrefix(p);if err!=nil{return err}
   for _,previous:=range all {
    if overlaps(canon,previous.prefix){return fmt.Errorf("write overlap %s:%s and %s:%s",c.ID,canon,previous.owner,previous.prefix)}
   }
   all=append(all,entry{c.ID,canon})
  }
 }
 return nil
}
func Schedule(m Manifest,statuses []Status)(Plan,error){
 if err:=Validate(m);err!=nil{return Plan{},err}
 selected:=map[string]Status{}
 for _,s:=range statuses{
  if s.ID=="" {return Plan{},errors.New("missing status ID")}
  if _,exists:=selected[s.ID];exists{return Plan{},fmt.Errorf("duplicate status %q",s.ID)}
  selected[s.ID]=s
 }
 lookup:=map[string]Cell{}; for _,c:=range m.Workcells{lookup[c.ID]=c}
 for id:=range selected {if _,known:=lookup[id];!known{return Plan{},fmt.Errorf("unrecognized status %s",id)}}
 p:=Plan{}
 var ready []Cell
 for _,c:=range m.Workcells {
  s,ok:=selected[c.ID];if !ok {s=Status{ID:c.ID,State:"NOT_STARTED"}}
  switch s.State {
  case "NOT_STARTED":ready=append(ready,c)
  case "RUNNING":p.Running=append(p.Running,c.ID)
  case "BLOCKED":if strings.TrimSpace(s.BlockedReason)==""{return Plan{},fmt.Errorf("missing blocker reason %s",c.ID)};p.Blocked=append(p.Blocked,s)
  case "RED":p.Blocked=append(p.Blocked,Status{ID:c.ID,State:s.State,BlockedReason:"RED requires explicit repair/evidence before retry"})
  case "QUALIFIED_TEST_ONLY","QUALIFIED_PRODUCTION": // Do not repeat a completed cell.
  default:return Plan{},fmt.Errorf("unknown state %s=%q",c.ID,s.State)
  }
 }
 sort.Strings(p.Running)
 sort.SliceStable(ready,func(i,j int)bool{
  if ready[i].Priority!=ready[j].Priority{return ready[i].Priority<ready[j].Priority}
  return ready[i].ID<ready[j].ID
 })
 slots:=m.MaxConcurrent-len(p.Running);if slots<0{return Plan{},errors.New("oversubscribed execution slots")}
 if slots>len(ready){slots=len(ready)}
 p.Admit=append(p.Admit,ready[:slots]...)
 if len(p.Running)+len(p.Admit)<m.MinIndependentActive {
  p.Shortfall=m.MinIndependentActive-len(p.Running)-len(p.Admit)
  p.NotReadyReason="insufficient ready/running independent workcells; inspect BLOCKED/RED/completed states, then refill DLE"
 }
 return p,nil
}
