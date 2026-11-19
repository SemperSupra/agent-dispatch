package batchplanner

import (
 "errors"
 "fmt"
 "regexp"
 "strings"
)

// Receipt is a MACHINE-VALIDATABLE claim, not a GitHub API verification.
// A supervisor must independently fetch first-hand Actions run/job/log status
// before entering QUALIFIED_TEST_ONLY into the authoritative private DLE.
type Receipt struct {
 ID string `json:"id"`
 DLE int `json:"dle"`
 Branch string `json:"branch"`
 HeadSHA string `json:"head_sha"`
 RunID int64 `json:"run_id"`
 JobIDs []int64 `json:"job_ids"`
 State string `json:"state"`
 Assertions map[string]string `json:"assertions"`
 Limitations []string `json:"limitations"`
 FailureReason string `json:"failure_reason,omitempty"`
 ArtifactIDs []int64 `json:"artifact_ids,omitempty"`
}

var sha40=regexp.MustCompile("^[0-9a-f]{40}$")

// CheckReceipts forbids evidence-free promotion and stale-head reuse.
// It intentionally refuses production qualification; those controls require
// genuine independently authenticated sources and a separate owner gate.
func CheckReceipts(m Manifest,currentHeads map[string]string,receipts []Receipt) error {
 if err:=Validate(m);err!=nil{return err}
 owned:=map[string]Cell{}
 for _,c:=range m.Workcells{owned[c.ID]=c}
 used:=map[string]bool{}
 usedRuns:=map[int64]string{}
 for _,r:=range receipts {
  c,ok:=owned[r.ID];if !ok{return fmt.Errorf("unknown receipt workcell %q",r.ID)}
  if used[r.ID]{return fmt.Errorf("duplicate receipt %s",r.ID)}
  used[r.ID]=true
  if r.Branch!=c.Branch || r.DLE!=c.DLE {return fmt.Errorf("receipt ownership mismatch %s",r.ID)}
  if r.State=="QUALIFIED_PRODUCTION" {return errors.New("unsupported production qualification: protected guest attestation and owner gate required")}
  switch r.State {
  case "NOT_STARTED":
   if r.RunID!=0 || len(r.JobIDs)!=0{return fmt.Errorf("unstarted receipt carries run %s",r.ID)}
  case "BLOCKED":
   if strings.TrimSpace(r.FailureReason)==""{return fmt.Errorf("unexplained blocker %s",r.ID)}
  case "RUNNING":
   if r.RunID<=0{return fmt.Errorf("running without submitted run %s",r.ID)}
  case "RED","QUALIFIED_TEST_ONLY":
   if !sha40.MatchString(r.HeadSHA){return fmt.Errorf("missing immutable source hash %s",r.ID)}
   if currentHeads[r.ID]!=r.HeadSHA{return fmt.Errorf("stale or unknown current head %s",r.ID)}
   if r.RunID<=0 || len(r.JobIDs)==0{return fmt.Errorf("no first-hand run/job receipt %s",r.ID)}
   if prior,exists:=usedRuns[r.RunID];exists {return fmt.Errorf("ambiguous shared run %d between %s and %s",r.RunID,prior,r.ID)}
   usedRuns[r.RunID]=r.ID
   seenJobs:=map[int64]bool{}
   for _,id:=range r.JobIDs{if id<=0||seenJobs[id]{return fmt.Errorf("invalid or duplicate job %s",r.ID)};seenJobs[id]=true}
   if len(r.Assertions)==0{return fmt.Errorf("no falsifiable evidence markers %s",r.ID)}
   pass,red,untested:=false,false,false
   for marker,status:=range r.Assertions{
    if marker=="" || (status!="PASS"&&status!="RED"&&status!="NOT_TESTED"){return fmt.Errorf("invalid assertion %s:%q",r.ID,marker)}
    if status=="PASS"{pass=true}
    if status=="RED"{red=true}
    if status=="NOT_TESTED"{untested=true}
   }
   if r.State=="RED" && (!red || strings.TrimSpace(r.FailureReason)==""){return fmt.Errorf("RED lacks original failure evidence %s",r.ID)}
   if r.State=="QUALIFIED_TEST_ONLY" && (!pass || red || !untested || len(r.Limitations)==0){
    return fmt.Errorf("invalid or overstated qualified test-only receipt %s",r.ID)
   }
  default:return fmt.Errorf("unsupported receipt state %s",r.State)
  }
 }
 return nil
}
