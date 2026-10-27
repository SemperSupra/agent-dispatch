package main

// Read-only check of GitHub's own run, matrix jobs, and retained artifacts.
// This is NOT a cryptographic hardware attestation or a decryption check.
import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "strconv"
 "strings"
)
type nativeJobs struct {
 TotalCount int `json:"total_count"`
 Jobs []struct {
  ID int64 `json:"id"`
  RunID int64 `json:"run_id"`
  RunAttempt int `json:"run_attempt"`
  Name string `json:"name"`
  HeadSHA string `json:"head_sha"`
  Status string `json:"status"`
  Conclusion *string `json:"conclusion"`
 } `json:"jobs"`
}
type nativeArtifacts struct {
 TotalCount int `json:"total_count"`
 Artifacts []struct {
  ID int64 `json:"id"`
  Name string `json:"name"`
  Expired bool `json:"expired"`
  Size int64 `json:"size_in_bytes"`
  WorkflowRun struct {ID int64 `json:"id"`;HeadSHA string `json:"head_sha"`} `json:"workflow_run"`
 } `json:"artifacts"`
}
type NativePairCheck struct {
 Schema string `json:"schema"`
 AssignmentID string `json:"assignment_id"`
 RunID string `json:"run_id"`
 State string `json:"state"`
 ArmJobsMatched int `json:"arm_jobs_matched"`
 ArmArtifactsMatched int `json:"arm_artifacts_matched"`
 ScientificStatus string `json:"scientific_status"`
}
func requestPublicJSON(ctx context.Context,c *http.Client,target string,out any)error{
 req,e:=http.NewRequestWithContext(ctx,"GET",target,nil);if e!=nil{return e}
 req.Header.Set("Accept","application/vnd.github+json")
 req.Header.Set("X-GitHub-Api-Version","2022-11-28")
 resp,e:=c.Do(req);if e!=nil{return e};defer resp.Body.Close()
 if resp.StatusCode!=200{return fmt.Errorf("GitHub native read HTTP %d",resp.StatusCode)}
 b,e:=io.ReadAll(io.LimitReader(resp.Body,maxJSON+1));if e!=nil{return e}
 if len(b)>maxJSON{return errors.New("native response exceeds bounded payload")}
 return json.Unmarshal(b,out)
}
func checkNativePairMetadata(ctx context.Context,c *http.Client,apiURL string,p PairPlan)(NativePairCheck,error){
 var result NativePairCheck
 if err:=validatePairPlan(p);err!=nil{return result,err}
 runID,e:=strconv.ParseInt(p.RunID,10,64);if e!=nil{return result,e}
 attempt,e:=strconv.Atoi(p.RunAttempt);if e!=nil||attempt<1{return result,errors.New("invalid native run attempt")}
 root:=strings.TrimSuffix(apiURL,"/")
 if root==""{return result,errors.New("missing native read origin")}
 var run APIRun
 if e=requestPublicJSON(ctx,c,root+"/actions/runs/"+p.RunID,&run);e!=nil{return result,e}
 if run.ID!=runID||run.Repository.FullName!=repo||run.Path!=workflow||
 run.HeadSHA!=p.SourceSHA||run.RunAttempt!=attempt||
 run.Status!="completed"||run.Conclusion==nil||*run.Conclusion!="success"||
 (run.Event!="issue_comment"&&run.Event!="workflow_dispatch") {
  return result,errors.New("native workflow run is not an accepted completed sweep")
 }
 var jobs nativeJobs
 if e=requestPublicJSON(ctx,c,root+"/actions/runs/"+p.RunID+"/jobs?per_page=100",&jobs);e!=nil{return result,e}
 if jobs.TotalCount!=len(jobs.Jobs)||jobs.TotalCount>100{return result,errors.New("incomplete native job enumeration")}
 seenJobs:=map[int64]bool{}
 for _,j:=range jobs.Jobs{
  if seenJobs[j.ID]{return result,errors.New("duplicate native job identity")}
  seenJobs[j.ID]=true
 }
 var artifacts nativeArtifacts
 if e=requestPublicJSON(ctx,c,root+"/actions/runs/"+p.RunID+"/artifacts?per_page=100",&artifacts);e!=nil{return result,e}
 if artifacts.TotalCount!=len(artifacts.Artifacts)||artifacts.TotalCount>100{return result,errors.New("incomplete native artifact enumeration")}
 seenArtifacts:=map[int64]bool{}
 for _,a:=range artifacts.Artifacts{
  if seenArtifacts[a.ID]{return result,errors.New("duplicate native artifact identity")}
  seenArtifacts[a.ID]=true
 }
 for _,arm:=range p.Arms{
  jid,e:=strconv.ParseInt(arm.JobID,10,64);if e!=nil{return result,e}
  aid,e:=strconv.ParseInt(arm.ArtifactID,10,64);if e!=nil{return result,e}
  expectedJob:="Sealed "+arm.Arm+" Stage-R independent GHA workcell"
  expectedArtifact:="mcp-gha-"+arm.Arm+"-sealed-"+p.RunID+"-"+p.RunAttempt
  jobCount:=0
  for _,j:=range jobs.Jobs{
   if j.ID!=jid{continue}
   if j.RunID!=runID||j.RunAttempt!=attempt||j.Name!=expectedJob||
    j.HeadSHA!=p.SourceSHA||j.Status!="completed"||
    j.Conclusion==nil||*j.Conclusion!="success"{
    return result,fmt.Errorf("native %s workcell job mismatch",arm.Arm)
   }
   jobCount++
  }
  if jobCount!=1{return result,fmt.Errorf("missing native %s job",arm.Arm)}
  artifactCount:=0
  for _,a:=range artifacts.Artifacts{
   if a.ID!=aid{continue}
   if a.Name!=expectedArtifact||a.Expired||a.Size<=0||
    a.WorkflowRun.ID!=runID||a.WorkflowRun.HeadSHA!=p.SourceSHA{
    return result,fmt.Errorf("native %s sealed mailbox mismatch",arm.Arm)
   }
   artifactCount++
  }
  if artifactCount!=1{return result,fmt.Errorf("missing native %s artifact",arm.Arm)}
 }
 return NativePairCheck{
  Schema:"mcp-gha-native-pair-metadata/v1",AssignmentID:p.AssignmentID,RunID:p.RunID,
  State:"NATIVE_GITHUB_METADATA_MATCH_ONLY_NOT_DECRYPTED",
  ArmJobsMatched:2,ArmArtifactsMatched:2,
  ScientificStatus:"SYNTHETIC_ONLY_NOT_VALIDATED",
 },nil
}
