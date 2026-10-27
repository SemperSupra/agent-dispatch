package main

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strconv"
 "strings"
 "testing"
)

func TestNativePairMetadataAndNegativeControls(t *testing.T){
 _,_,p:=pairedFixture(t)
 runID,_:=strconv.ParseInt(p.RunID,10,64)
 attempt:=1
 conclusion:="success"
 makeRun:=func()APIRun{
  return APIRun{ID:runID,Name:"comment-wake",Path:workflow,
   Event:"issue_comment",Status:"completed",Conclusion:&conclusion,
   RunAttempt:attempt,HeadSHA:p.SourceSHA,Repository:APIRepository{FullName:repo}}
 }
 jobs:=nativeJobs{TotalCount:2}
 artifacts:=nativeArtifacts{TotalCount:2}
 for _,a:=range p.Arms{
  id,_:=strconv.ParseInt(a.JobID,10,64)
  aid,_:=strconv.ParseInt(a.ArtifactID,10,64)
  item:=struct{
   ID int64 `json:"id"`
   RunID int64 `json:"run_id"`
   RunAttempt int `json:"run_attempt"`
   Name string `json:"name"`
   HeadSHA string `json:"head_sha"`
   Status string `json:"status"`
   Conclusion *string `json:"conclusion"`
  }{id,runID,attempt,"Sealed "+a.Arm+" Stage-R independent GHA workcell",p.SourceSHA,"completed",&conclusion}
  jobs.Jobs=append(jobs.Jobs,item)
  art:=struct{
   ID int64 `json:"id"`
   Name string `json:"name"`
   Expired bool `json:"expired"`
   Size int64 `json:"size_in_bytes"`
   WorkflowRun struct{ID int64 `json:"id"`;HeadSHA string `json:"head_sha"`} `json:"workflow_run"`
  }{}
  art.ID=aid;art.Name="mcp-gha-"+a.Arm+"-sealed-"+p.RunID+"-"+p.RunAttempt
  art.Size=1234;art.WorkflowRun.ID=runID;art.WorkflowRun.HeadSHA=p.SourceSHA
  artifacts.Artifacts=append(artifacts.Artifacts,art)
 }
 native:=makeRun()
 var testSrv *httptest.Server
 testSrv=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  if !strings.HasPrefix(r.URL.Path,"/actions/runs/"+p.RunID){t.Errorf("unexpected path %s",r.URL)}
  switch r.URL.Path{
  case "/actions/runs/"+p.RunID:
   _=json.NewEncoder(w).Encode(native)
  case "/actions/runs/"+p.RunID+"/jobs":
   if r.URL.Query().Get("per_page")!="100"{t.Error("nonexhaustive jobs request")}
   _=json.NewEncoder(w).Encode(jobs)
  case "/actions/runs/"+p.RunID+"/artifacts":
   if r.URL.Query().Get("per_page")!="100"{t.Error("nonexhaustive artifacts request")}
   _=json.NewEncoder(w).Encode(artifacts)
  default:w.WriteHeader(404)
  }
 }))
 defer testSrv.Close()
 expect:=func(name string,valid bool){
  t.Helper()
  r,e:=checkNativePairMetadataAt(context.Background(),testSrv.Client(),testSrv.URL,p)
  if valid{
   if e!=nil||r.ArmJobsMatched!=2||r.ArmArtifactsMatched!=2||r.State!="NATIVE_GITHUB_METADATA_MATCH_ONLY_NOT_DECRYPTED"{t.Fatalf("%s: %+v, %v",name,r,e)}
  }else if e==nil{t.Fatalf("%s accepted invalid metadata: %+v",name,r)}
 }
 expect("valid",true)
 native.Status="in_progress";expect("unfinished-run",false);native=makeRun()
 native.Event="pull_request";expect("unadmitted-event",false);native=makeRun()
 native.HeadSHA=strings.Repeat("f",40);expect("different-source-sha",false);native=makeRun()
 jobs.Jobs[0].Conclusion=nil;expect("unfinished-arm",false);jobs.Jobs[0].Conclusion=&conclusion
 jobs.Jobs[1].RunAttempt=2;expect("stale-arm-attempt",false);jobs.Jobs[1].RunAttempt=1
 jobs.TotalCount=3;expect("partial-job-list",false);jobs.TotalCount=2
 artifacts.Artifacts[0].Expired=true;expect("expired-ciphertext",false);artifacts.Artifacts[0].Expired=false
 artifacts.Artifacts[1].Name="other-mailbox";expect("wrong-mailbox",false)
 artifacts.Artifacts[1].Name="mcp-gha-cpe-sealed-"+p.RunID+"-"+p.RunAttempt
 artifacts.Artifacts[1].WorkflowRun.HeadSHA=strings.Repeat("a",39)+"b"
 expect("wrong-artifact-source",false)
 artifacts.Artifacts[1].WorkflowRun.HeadSHA=p.SourceSHA
 artifacts.TotalCount=3;expect("partial-artifact-list",false)
}
