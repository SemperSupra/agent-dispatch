package main

// Per-arm Stage R request: consumes ONLY this arm's pre-frozen input.
// This is a public-safe transport schema, not a validation that a CPE
// projection came from the authoritative private CPE or that actors are blind.

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net/http"
 "time"
)

const armSchema = "mcp-gha-stage-r-arm/v1"

type ArmPlan struct {
 Schema string `json:"schema"`
 ID string `json:"id"`
 Arm string `json:"arm"`
 DataClass string `json:"data_class"`
 IntentRef string `json:"intent_ref"`
 QueryAuthorityRef string `json:"query_authority_ref"`
 ScienceClass string `json:"science_class"`
 Languages []string `json:"languages"`
 Queries []Query `json:"queries"`
 SearxngImage string `json:"searxng_image_digest"`
 ConfigSHA256 string `json:"searxng_config_sha256"`
}

type ArmResult struct {
 Schema string `json:"schema"`
 PlanID string `json:"plan_id"`
 Arm string `json:"arm"`
 PlanSHA256 string `json:"plan_sha256"`
 ScienceClass string `json:"science_class"`
 AuthorityRef string `json:"query_authority_ref"`
 AuthorityStatus string `json:"authority_status"`
 SearxngImage string `json:"searxng_image_digest"`
 ConfigSHA256 string `json:"searxng_config_sha256"`
 RuntimeUTC string `json:"runtime_utc"`
 TerminalState string `json:"terminal_state"`
 Planned int `json:"planned_requests"`
 Attempted int `json:"attempted_network"`
 Succeeded int `json:"succeeded_provider"`
 Failed int `json:"failed_provider"`
 Attempts []Attempt `json:"attempts"`
}

func validateArm(p ArmPlan) error {
 if p.Schema!=armSchema||!identRE.MatchString(p.ID)||p.IntentRef==""||p.DataClass!="public-reviewed" {
  return errors.New("invalid release-approved arm plan")
 }
 if p.Arm!="reference"&&p.Arm!="cpe"{return errors.New("invalid arm")}
 // Synthetic canaries are the only accepted submitted input class until
 // authoritative CPE attestation and separate blind custody earn acceptance.
 if p.ScienceClass!="SYNTHETIC_TRANSPORT_ONLY"||p.QueryAuthorityRef!="SYNTHETIC_TEST_ONLY_NOT_CPE_AUTHORITY" {
  return errors.New("real CPE or reference authority is not admitted on public pilot")
 }
 if !imageRE.MatchString(p.SearxngImage)||!hex64.MatchString(p.ConfigSHA256) {
  return errors.New("unpinned search image or config")
 }
 if len(p.Languages)<3||len(p.Languages)>20{return errors.New("language coverage outside bounds")}
 allowed:=map[string]bool{}
 for _,lang:=range p.Languages {
  if !langRE.MatchString(lang)||allowed[lang]{return errors.New("bad or duplicate language")}
  allowed[lang]=true
 }
 return validateQueries(p.Queries,allowed)
}

func runArm(ctx context.Context,p ArmPlan,bytes []byte,endpoint string,client *http.Client)(ArmResult,error){
 if err:=validateArm(p);err!=nil{return ArmResult{},err}
 if err:=endpointOK(endpoint);err!=nil{return ArmResult{},err}
 r:=ArmResult{
  Schema:"mcp-gha-stage-r-arm-result/v1",PlanID:p.ID,Arm:p.Arm,
  PlanSHA256:digest(bytes),ScienceClass:p.ScienceClass,AuthorityRef:p.QueryAuthorityRef,
  AuthorityStatus:"SYNTHETIC_NO_CPE_AUTHORITY_ATTESTATION",
  SearxngImage:p.SearxngImage,ConfigSHA256:p.ConfigSHA256,
  RuntimeUTC:time.Now().UTC().Format(time.RFC3339),
  TerminalState:"TREATMENT_PATH_DEFECT",Planned:len(p.Queries),Attempts:[]Attempt{},
 }
 for i,q:=range p.Queries{
  began:=time.Now()
  a:=search(ctx,client,endpoint,p.Arm,i,q)
  a.ElapsedMs=time.Since(began).Milliseconds()
  r.Attempts=append(r.Attempts,a)
  r.Attempted++
  if a.State=="SUCCEEDED_PROVIDER"{r.Succeeded++}else{r.Failed++}
 }
 if r.Failed==0{r.TerminalState="RETRIEVAL_PASS"}else if r.Succeeded==0{r.TerminalState="SOURCE_EXECUTOR_GAP"}else{r.TerminalState="PARTIAL"}
 return r,nil
}
func runArmFile(ctx context.Context,input string,endpoint string,client *http.Client)(ArmResult,error){
 var plan ArmPlan
 b,err:=readJSON(input,&plan)
 if err!=nil{return ArmResult{},fmt.Errorf("read arm: %w",err)}
 return runArm(ctx,plan,b,endpoint,client)
}
func marshalArm(r ArmResult)([]byte,error){return json.MarshalIndent(r,"","  ")}
