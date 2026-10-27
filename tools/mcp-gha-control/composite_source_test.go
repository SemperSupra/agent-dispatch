package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
)

func compositeFixture(t *testing.T)(string,string,PairPlan){
 t.Helper()
 manifest,inbox,p:=pairedFixture(t)
 p.Schema="mcp-gha-private-pair-preflight/v2"
 p.Workflow=qualificationWorkflow
 p.WorkflowSourceSHA=strings.Repeat("e",40)
 p.SourceSHA=syntheticCollectorSource
 for i,arm:=range p.Arms {
  name:=filepath.Join(inbox,arm.Arm,"receipt.json")
  var receipt Receipt
  if _,e:=readJSON(name,&receipt);e!=nil{t.Fatal(e)}
  receipt.SourceSHA=p.SourceSHA
  saveReceipt(t,name,receipt)
  contents,e:=os.ReadFile(name);if e!=nil{t.Fatal(e)}
  sum:=sha256.Sum256(contents)
  p.Arms[i].ReceiptSHA256=hex.EncodeToString(sum[:])
 }
 savePair(t,manifest,p)
 return manifest,inbox,p
}
func TestCompositeSourcePreflightAndEnforcedVersion(t *testing.T){
 manifest,inbox,p:=compositeFixture(t)
 if _,err:=pairPreflight(manifest,inbox);err!=nil{t.Fatal(err)}
 if p.WorkflowSourceSHA==p.SourceSHA{t.Fatal("composite fixture must use distinct provenance")}
 for _,tc:=range []struct{name string;bad func(*PairPlan)}{
  {"missing-workflow-sha",func(x *PairPlan){x.WorkflowSourceSHA=""}},
  {"workflow-sha-invalid",func(x *PairPlan){x.WorkflowSourceSHA="not-a-commit"}},
  {"wrong-workflow",func(x *PairPlan){x.Workflow=workflow}},
  {"wrong-collector-source",func(x *PairPlan){x.SourceSHA=strings.Repeat("f",40)}},
  {"arbitrary-third-schema",func(x *PairPlan){x.Schema="mcp-gha-private-pair-preflight/v3"}},
  {"v1-rejects-composite-fields",func(x *PairPlan){x.Schema="mcp-gha-private-pair-preflight/v1";x.Workflow=workflow}},
 }{
  t.Run(tc.name,func(t *testing.T){
   x:=p;tc.bad(&x);savePair(t,manifest,x)
   if _,err:=pairPreflight(manifest,inbox);err==nil{t.Fatal("invalid composite source admitted")}
   savePair(t,manifest,p)
  })
 }
}
func TestNativeCompositeSourceGitHubWorkflowVsCollector(t *testing.T){
 _,_,p:=compositeFixture(t)
 runID,_:=strconv.ParseInt(p.RunID,10,64)
 finished:="success"
 apiRun:=APIRun{ID:runID,Path:qualificationWorkflow,
  Event:"pull_request",Status:"completed",Conclusion:&finished,
  RunAttempt:1,HeadSHA:p.WorkflowSourceSHA,Repository:APIRepository{FullName:repo}}
 jobList:=nativeJobs{TotalCount:2}
 artifacts:=nativeArtifacts{TotalCount:2}
 for _,arm:=range p.Arms{
  jid,_:=strconv.ParseInt(arm.JobID,10,64)
  aid,_:=strconv.ParseInt(arm.ArtifactID,10,64)
  jobList.Jobs=append(jobList.Jobs,struct{
   ID int64 `json:"id"`;RunID int64 `json:"run_id"`
   RunAttempt int `json:"run_attempt"`;Name string `json:"name"`
   HeadSHA string `json:"head_sha"`;Status string `json:"status"`
   Conclusion *string `json:"conclusion"`
  }{jid,runID,1,"Synthetic sealed "+arm.Arm+" GHA arm",p.WorkflowSourceSHA,"completed",&finished})
  var artifact struct{
   ID int64 `json:"id"`;Name string `json:"name"`
   Expired bool `json:"expired"`;Size int64 `json:"size_in_bytes"`
   WorkflowRun struct{ID int64 `json:"id"`;HeadSHA string `json:"head_sha"`} `json:"workflow_run"`
  }
  artifact.ID=aid;artifact.Name="mcp-gha-artifact-test-"+arm.Arm+"-"+p.RunID+"-"+p.RunAttempt
  artifact.Size=128;artifact.WorkflowRun.ID=runID;artifact.WorkflowRun.HeadSHA=p.WorkflowSourceSHA
  artifacts.Artifacts=append(artifacts.Artifacts,artifact)
 }
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  switch r.URL.Path{
  case "/actions/runs/"+p.RunID:_=json.NewEncoder(w).Encode(apiRun)
  case "/actions/runs/"+p.RunID+"/jobs":_=json.NewEncoder(w).Encode(jobList)
  case "/actions/runs/"+p.RunID+"/artifacts":_=json.NewEncoder(w).Encode(artifacts)
  default:w.WriteHeader(404)
  }
 }))
 defer server.Close()
 test:=func(label string,expected bool){
  t.Helper()
  state,err:=checkNativePairMetadataAt(context.Background(),server.Client(),server.URL,p)
  if expected {
   if err!=nil||state.ArmJobsMatched!=2||state.ArmArtifactsMatched!=2{t.Fatalf("%s: state=%+v error=%v",label,state,err)}
  } else if err==nil{t.Fatalf("%s unexpectedly admitted",label)}
 }
 test("valid-composite",true)
 apiRun.HeadSHA=p.SourceSHA;test("wrongly-bind-to-collector-sha",false);apiRun.HeadSHA=p.WorkflowSourceSHA
 apiRun.Path=workflow;test("wrong-workflow",false);apiRun.Path=qualificationWorkflow
 apiRun.Event="workflow_dispatch";test("wrong-event-for-synthetic",false);apiRun.Event="pull_request"
 jobList.Jobs[0].HeadSHA=p.SourceSHA;test("false-native-job-sha",false);jobList.Jobs[0].HeadSHA=p.WorkflowSourceSHA
 jobList.Jobs[0].Name="Sealed reference Stage-R independent GHA workcell";test("wrong-job-class",false);jobList.Jobs[0].Name="Synthetic sealed reference GHA arm"
 artifacts.Artifacts[0].WorkflowRun.HeadSHA=p.SourceSHA;test("false-artifact-workflow-sha",false);artifacts.Artifacts[0].WorkflowRun.HeadSHA=p.WorkflowSourceSHA
 artifacts.Artifacts[1].Name="mcp-gha-cpe-sealed-"+p.RunID+"-"+p.RunAttempt;test("production-artifact-in-synthetic",false)
}
