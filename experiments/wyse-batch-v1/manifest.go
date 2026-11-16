// Offline static weak-model batch packet validator; no scheduling/dispatch.
package batchv1
import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "path"
 "regexp"
 "strings"
)
type Packet struct{
 Workcell string `json:"workcell"`
 Issue int `json:"issue"`
 Branch string `json:"branch"`
 AllowedPaths []string `json:"allowed_paths"`
 SourceSHA string `json:"source_sha"`
 Runner string `json:"runner"`
 Workflow string `json:"workflow"`
 PositiveOracle string `json:"positive_oracle"`
 NegativeOracle string `json:"negative_oracle"`
 CleanupOracle string `json:"cleanup_oracle"`
 TimeoutMinutes int `json:"timeout_minutes"`
 RetryLimit int `json:"retry_limit"`
 MaxParallel int `json:"max_parallel"`
 FailFast bool `json:"fail_fast"`
 DisposableOCI bool `json:"disposable_oci"`
 UsesPhysical bool `json:"uses_physical"`
 WritesProduction bool `json:"writes_production"`
}
type Manifest struct{
 Schema int `json:"schema"`
 BatchID string `json:"batch_id"`
 Workcells []Packet `json:"workcells"`
}
var (
 nameRE=regexp.MustCompile(`^[a-z][a-z0-9-]{2,60}$`)
 shaRE=regexp.MustCompile(`^[a-f0-9]{40}$`)
 branchRE=regexp.MustCompile(`^test/issue-[0-9]+-[a-z0-9][a-z0-9-]*$`)
)
func safePath(p string)bool{
 if p==""||p=="."||strings.HasPrefix(p,"/")||strings.ContainsRune(p,rune(92))||
  strings.Contains(p,"*")||strings.Contains(p,":")||
  strings.Contains(p,"\x00")||path.Clean(p)!=p{return false}
 for _,seg:=range strings.Split(p,"/"){
  if seg==""||seg=="."||seg==".."||seg==".git"{return false}
 }
 if p=="experiments"||p==".github"||p==".github/workflows"{return false}
 return true
}
func collide(a,b string)bool {
 return a==b||strings.HasPrefix(a,b+"/")||strings.HasPrefix(b,a+"/")
}
func Parse(data []byte)(Manifest,error){
 var m Manifest
 d:=json.NewDecoder(strings.NewReader(string(data)))
 d.DisallowUnknownFields()
 if e:=d.Decode(&m);e!=nil{return m,e}
 var extra any
 if e:=d.Decode(&extra);e!=io.EOF{return m,errors.New("trailing input")}
 if m.Schema!=1||!nameRE.MatchString(m.BatchID)||len(m.Workcells)<1||len(m.Workcells)>3{
  return m,errors.New("batch schema, ID or WIP cap invalid")
 }
 issues:=map[int]bool{}
 names:=map[string]bool{}
 branches:=map[string]bool{}
 paths:=map[string]string{}
 for _,p:=range m.Workcells{
  if !nameRE.MatchString(p.Workcell)||names[p.Workcell]{return m,errors.New("duplicate/invalid workcell")}
  names[p.Workcell]=true
  if p.Issue<1||issues[p.Issue]{return m,errors.New("duplicate/invalid workcell issue")}
  issues[p.Issue]=true
  if !branchRE.MatchString(p.Branch)||branches[p.Branch]||
   !strings.HasPrefix(p.Branch,fmt.Sprintf("test/issue-%d-",p.Issue)){
    return m,errors.New("branch not issue linked or duplicate")
  }
  branches[p.Branch]=true
  if !shaRE.MatchString(p.SourceSHA)||p.SourceSHA==strings.Repeat("0",40){
   return m,errors.New("missing exact source pin")
  }
  if p.Runner!="ubuntu-24.04"||!p.DisposableOCI||p.UsesPhysical||p.WritesProduction{
   return m,errors.New("unsafe runner, host mutation, physical or production effect")
  }
  if p.FailFast||p.MaxParallel<1||p.MaxParallel>3||p.TimeoutMinutes<1||
   p.TimeoutMinutes>30||p.RetryLimit<0||p.RetryLimit>2{
   return m,errors.New("unbounded or serializing execution budget")
  }
  if !strings.HasSuffix(p.PositiveOracle,"=PASS")||
   p.NegativeOracle==""||strings.Contains(strings.ToLower(p.NegativeOracle),"not tested")||
   !strings.HasSuffix(p.CleanupOracle,"=PASS"){
   return m,errors.New("missing positive, negative or disposal evidence")
  }
  if !safePath(p.Workflow)||!strings.HasPrefix(p.Workflow,".github/workflows/")||
    !(strings.HasSuffix(p.Workflow,".yml")||strings.HasSuffix(p.Workflow,".yaml")){
   return m,errors.New("unbounded workflow")
  }
  if len(p.AllowedPaths)<2||len(p.AllowedPaths)>8{return m,errors.New("missing/broad source allowlist")}
  workflowIncluded:=false
  for _,pathName:=range p.AllowedPaths {
   if !safePath(pathName){return m,errors.New("unsafe allowed path")}
   if pathName==p.Workflow{workflowIncluded=true}
   for existing,worker:=range paths{
    if collide(pathName,existing){
     return m,fmt.Errorf("overlap %q and %q between %s and %s",pathName,existing,p.Workcell,worker)
    }
   }
   paths[pathName]=p.Workcell
  }
  if !workflowIncluded{return m,errors.New("workflow missing from allowed paths")}
 }
 return m,nil
}
