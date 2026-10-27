// MCP GHA control observer: read-only, public Actions run and encrypted mailbox.
// GitHub is executor truth. This tool NEVER converts green CI into semantic PASS.
package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net/http"
 "os"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "time"
)

const (
 repo = "SemperSupra/agent-dispatch"
 workflow = ".github/workflows/mcp-gha-worker.yml"
 apiBase = "https://api.github.com/repos/SemperSupra/agent-dispatch/actions/runs/"
 maxJSON = 1024*1024
 maxCiphertext = 16*1024*1024
)
var digits=regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var hex40=regexp.MustCompile(`^[0-9a-f]{40}$`)
var hex64=regexp.MustCompile(`^[0-9a-f]{64}$`)
var pinnedSearxImage=regexp.MustCompile(`^ghcr[.]io/searxng/searxng:[a-zA-Z0-9.-]+@sha256:[0-9a-f]{64}$`)

type APIRepository struct { FullName string `json:"full_name"` }
type APIRun struct {
 ID int64 `json:"id"`
 Name string `json:"name"`
 Path string `json:"path"`
 Event string `json:"event"`
 Status string `json:"status"`
 Conclusion *string `json:"conclusion"`
 HeadSHA string `json:"head_sha"`
 URL string `json:"html_url"`
 CreatedAt string `json:"created_at"`
 UpdatedAt string `json:"updated_at"`
 RunAttempt int `json:"run_attempt"`
 Repository APIRepository `json:"repository"`
}
type Observation struct {
 Schema string `json:"schema"`
 RunID int64 `json:"run_id"`
 Repository string `json:"repository"`
 NativeRunStatus string `json:"native_run_status"`
 NativeConclusion string `json:"native_conclusion"`
 ControlState string `json:"control_state"`
 ScienceState string `json:"science_state"`
 Event string `json:"event"`
 SourceSHA string `json:"source_sha"`
 RunAttempt int `json:"run_attempt"`
 RunURL string `json:"run_url"`
}
type Receipt struct {
 Schema string `json:"schema"`
 ScienceValid bool `json:"science_valid"`
 TreatmentAuthenticity string `json:"treatment_authenticity"`
 PublicRunID string `json:"public_run_id"`
 PublicRunAttempt string `json:"public_run_attempt"`
 SourceSHA string `json:"source_sha"`
 PlanSHA256 string `json:"plan_sha256"`
 ProjectionSHA256 string `json:"projection_sha256"`
 SearxngImageDigest string `json:"searxng_image_digest"`
 SearxngConfigSHA256 string `json:"searxng_config_sha256"`
 TerminalState string `json:"terminal_state"`
 Attempted int `json:"attempted"`
 Succeeded int `json:"succeeded"`
 Failed int `json:"failed"`
 CiphertextSHA256 string `json:"ciphertext_sha256"`
 CiphertextBytes int64 `json:"ciphertext_bytes"`
 Arm string `json:"arm,omitempty"`
 ResearchStatus string `json:"research_status,omitempty"`
 RunID string `json:"run_id,omitempty"`
 RunAttempt string `json:"run_attempt,omitempty"`
 ProviderImageDigest string `json:"provider_image_digest,omitempty"`
 ConfigSHA256 string `json:"config_sha256,omitempty"`
 ImagePullMS *int64 `json:"image_pull_ms,omitempty"`
 ProviderReadyMS *int64 `json:"provider_ready_ms,omitempty"`
 GoBuildMS *int64 `json:"go_build_ms,omitempty"`
 PrewarmedImageVerifyMS *int64 `json:"prewarmed_image_verify_ms,omitempty"`
 RunnerPreparedOnce *bool `json:"runner_prepared_once,omitempty"`
}
type Verification struct {
 Schema string `json:"schema"`
 RunID string `json:"run_id"`
 CiphertextVerified bool `json:"ciphertext_verified"`
 ArtifactState string `json:"artifact_state"`
 ScienceState string `json:"science_state"`
 TerminalState string `json:"reported_stage_r_terminal_state"`
 Arm string `json:"arm,omitempty"`
 SourceSHA string `json:"receipt_source_sha"`
 RunAttempt string `json:"run_attempt"`
 ReceiptTrust string `json:"receipt_trust"`
 Attempted int `json:"attempted"`
 Succeeded int `json:"succeeded"`
 Failed int `json:"failed"`
}

func readBounded(r io.Reader,limit int64) ([]byte,error) {
 b,err:=io.ReadAll(io.LimitReader(r,limit+1))
 if err!=nil{return nil,err}
 if int64(len(b))>limit{return nil,errors.New("JSON size limit")}
 return b,nil
}
func observe(ctx context.Context, client *http.Client, endpoint string,id string)(Observation,error){
 if !digits.MatchString(id){return Observation{},errors.New("invalid native run ID")}
 req,err:=http.NewRequestWithContext(ctx,"GET",endpoint+id,nil)
 if err!=nil{return Observation{},err}
 req.Header.Set("Accept","application/vnd.github+json")
 req.Header.Set("X-GitHub-Api-Version","2022-11-28")
 // Optional rate-limit-safe read token only to the compile-time fixed GitHub
 // origin; never forward credentials to a caller-provided endpoint.
 if endpoint==apiBase {
  if token:=os.Getenv("GITHUB_TOKEN");token!=""{req.Header.Set("Authorization","Bearer "+token)}
 }
 resp,err:=client.Do(req)
 if err!=nil{return Observation{},err}
 defer resp.Body.Close()
 if resp.StatusCode!=200{return Observation{},fmt.Errorf("github native read failed with HTTP %d",resp.StatusCode)}
 b,err:=readBounded(resp.Body,maxJSON);if err!=nil{return Observation{},err}
 var x APIRun
 if err:=json.Unmarshal(b,&x);err!=nil{return Observation{},err}
 parsed,_:=strconv.ParseInt(id,10,64)
 if x.ID!=parsed||x.Repository.FullName!=repo||x.Path!=workflow||!hex40.MatchString(x.HeadSHA)||x.RunAttempt<1{
  return Observation{},errors.New("native run identity, repository, source revision or workflow mismatch")
 }
 allowed:=map[string]bool{"queued":true,"in_progress":true,"completed":true,"waiting":true,"pending":true,"requested":true}
 if !allowed[x.Status]{return Observation{},errors.New("unknown native status")}
 concl:="UNKNOWN"
 if x.Conclusion!=nil{concl=*x.Conclusion}
 state:="OBSERVING_NATIVE"
 if x.Status=="completed" {
  switch concl {case "success":state="EXECUTOR_COMPLETE_EVIDENCE_NOT_VALIDATED"
  case "cancelled":state="CANCELLED_NATIVE"
  case "failure","timed_out","action_required","startup_failure":state="FAILED_NATIVE"
  case "skipped":state="NOT_ADMITTED_OR_SKIPPED"
  default:state="TERMINAL_UNCLASSIFIED"}
 }
 return Observation{Schema:"mcp-gha-control-observation/v1",RunID:x.ID,Repository:repo,NativeRunStatus:x.Status,NativeConclusion:concl,ControlState:state,ScienceState:"UNJUDGED_NEEDS_TRUSTED_PRIVATE_INGEST",Event:x.Event,SourceSHA:x.HeadSHA,RunAttempt:x.RunAttempt,RunURL:x.URL},nil
}
func loadReceipt(path string) (Receipt,error) {
 f,err:=os.Open(path);if err!=nil{return Receipt{},err};defer f.Close()
 b,err:=readBounded(f,32768);if err!=nil{return Receipt{},err}
 d:=json.NewDecoder(strings.NewReader(string(b)));d.DisallowUnknownFields()
 var r Receipt
 if err:=d.Decode(&r);err!=nil{return Receipt{},err}
 var extra any
 if err:=d.Decode(&extra);err!=io.EOF{return Receipt{},errors.New("trailing receipt data")}
 return r,nil
}
func verify(receiptPath, cipherPath string)(Verification,error){
 return verifyBound(receiptPath,cipherPath,"","")
}
func verifyBound(receiptPath, cipherPath, expectedRunID, expectedArm string)(Verification,error){
 r,err:=loadReceipt(receiptPath);if err!=nil{return Verification{},err}
 if !hex64.MatchString(r.CiphertextSHA256)||
 r.CiphertextBytes<1||r.CiphertextBytes>maxCiphertext||
 r.Attempted<1||r.Succeeded<0||r.Failed<0||r.Succeeded+r.Failed!=r.Attempted {
  return Verification{},errors.New("invalid ciphertext or network accounting")
 }
 nativeRunID:=""
 nativeAttempt:=""
 scienceState:="SYNTHETIC_ONLY_NO_CPE_AUTHORITY_OR_ADJUDICATION"
 switch r.Schema {
 case "mcp-gha-sealed-transport-canary/v1":
  if r.ScienceValid||r.TreatmentAuthenticity!="SYNTHETIC_TEST_ONLY_NOT_CPE_AUTHORITY"||
  !digits.MatchString(r.PublicRunID)||!digits.MatchString(r.PublicRunAttempt)||
  !hex40.MatchString(r.SourceSHA)||!hex64.MatchString(r.PlanSHA256)||
  !hex64.MatchString(r.ProjectionSHA256)||!hex64.MatchString(r.SearxngConfigSHA256)||
  r.Attempted!=6 || r.Arm!="" || expectedArm!="" {
   return Verification{},errors.New("invalid or unauthorized legacy synthetic receipt")
  }
  nativeRunID,nativeAttempt=r.PublicRunID,r.PublicRunAttempt
 case "mcp-gha-sealed-arm-receipt/v1":
  if r.ScienceValid||r.TreatmentAuthenticity!=""||
  !digits.MatchString(r.RunID)||!digits.MatchString(r.RunAttempt)||
  !hex40.MatchString(r.SourceSHA)||!hex64.MatchString(r.PlanSHA256)||
  !hex64.MatchString(r.ConfigSHA256)||
  (r.Arm!="reference"&&r.Arm!="cpe")||
  r.ResearchStatus!="SYNTHETIC_TRANSPORT_ONLY_NOT_BLIND_RESEARCH"||
  !pinnedSearxImage.MatchString(r.ProviderImageDigest)||
  r.Attempted!=3||
  r.ImagePullMS==nil||r.ProviderReadyMS==nil||r.GoBuildMS==nil||
  *r.ImagePullMS<0||*r.ProviderReadyMS<0||*r.GoBuildMS<0||
  r.RunnerPreparedOnce==nil||r.PrewarmedImageVerifyMS==nil||
  *r.PrewarmedImageVerifyMS<0||
  (r.TerminalState!="RETRIEVAL_PASS"&&r.TerminalState!="SOURCE_EXECUTOR_GAP"&&r.TerminalState!="PARTIAL") {
   return Verification{},errors.New("invalid or unqualified per-arm synthetic receipt")
  }
  // A swapped receipt from another arm or Actions run is rejected when
  // the expected identity is supplied by an independently admitted workset.
  nativeRunID,nativeAttempt=r.RunID,r.RunAttempt
 default:
  return Verification{},errors.New("unknown receipt schema")
 }
 if expectedRunID!="" && (!digits.MatchString(expectedRunID)||nativeRunID!=expectedRunID) {
  return Verification{},errors.New("run ID mismatches trusted expected identity")
 }
 if expectedArm!="" && r.Arm!=expectedArm {
  return Verification{},errors.New("receipt arm mismatches trusted expected identity")
 }
 if r.TerminalState=="RETRIEVAL_PASS"&&r.Failed!=0{
  return Verification{},errors.New("retrieval success conflicts with failed provider count")
 }
 if r.TerminalState=="SOURCE_EXECUTOR_GAP"&&r.Succeeded!=0{
  return Verification{},errors.New("source executor gap conflicts with provider success")
 }
 f,err:=os.Open(filepath.Clean(cipherPath));if err!=nil{return Verification{},err}
 defer f.Close()
 h:=sha256.New()
 n,err:=io.Copy(h,io.LimitReader(f,maxCiphertext+1));if err!=nil{return Verification{},err}
 if n!=r.CiphertextBytes||n>maxCiphertext||hex.EncodeToString(h.Sum(nil))!=r.CiphertextSHA256 {
  return Verification{},errors.New("ciphertext size or SHA256 mismatch")
 }
 return Verification{
  Schema:"mcp-gha-mailbox-verification/v1",RunID:nativeRunID,CiphertextVerified:true,
  ArtifactState:"CIPHERTEXT_DIGEST_MATCH_ONLY_NOT_DECRYPTED",
  ScienceState:scienceState,ReceiptTrust:"SELF_REPORTED_UNAUTHENTICATED_NEEDS_NATIVE_RUN_AND_PRIVATE_INGEST",
  Arm:r.Arm,SourceSHA:r.SourceSHA,RunAttempt:nativeAttempt,
  TerminalState:r.TerminalState,Attempted:r.Attempted,Succeeded:r.Succeeded,Failed:r.Failed,
 },nil
}
func describe()map[string]any {
 return map[string]any{
  "schema":"mcp-gha-control-discovery/v1",
  "name":"MCP GHA",
  "audiences":[]string{"human","automation","agent"},
  "controller":"GitHub native Actions / existing admitted Agent Dispatch",
  "science_state":"UNJUDGED_NEEDS_TRUSTED_PRIVATE_INGEST",
  "public_wake_issue_or_pr":"SemperSupra/agent-dispatch#553",
  "commands":map[string]string{
   "start_smoke":"/mcp gha start smoke",
   "pilot_after_review":"/mcp gha sweep pilot",
   "temporary_mcp_after_separate_approval":"/mcp gha start live",
  },
  "observe":"mcp-gha-control status --run-id <native GitHub run ID>",
  "verify":"mcp-gha-control verify-receipt --receipt <receipt.json> --ciphertext <result.age>",
  "stop_or_cancel":"GitHub Actions Cancel workflow; programmatic cancellation requires separately admitted Actions write authority",
  "artifact_contract":"mcp-gha-sealed-arm-receipt/v1",
  "outcomes":[]string{"REQUESTED","ADMITTED","QUEUED","RUNNING","SEALED","INGESTED","VALIDATED","BLOCKED","FAILED","CANCELLED","EXPIRED"},
  "limitations":[]string{"green Actions != validated sweep","encrypted result != private execution","synthetic transport canary != CPE-projected treatment","no blind scientific comparison within same workcell","no persistent result ingester yet"},
 }
}
func emit(x any)error {e:=json.NewEncoder(os.Stdout);e.SetIndent("","  ");return e.Encode(x)}
func main(){
 if len(os.Args)<2{fmt.Fprintln(os.Stderr,"usage: mcp-gha-control describe|status|verify-receipt|stage-pair");os.Exit(2)}
 switch os.Args[1]{
 case "describe":if len(os.Args)!=2{os.Exit(2)};_ = emit(describe())
 case "status":
  flags:=flag.NewFlagSet("status",flag.ExitOnError)
  id:=flags.String("run-id","","native GitHub run ID");_=flags.Parse(os.Args[2:])
  client:=&http.Client{Timeout:10*time.Second}
  obs,err:=observe(context.Background(),client,apiBase,*id)
  if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
  _=emit(obs)
 case "stage-pair":
  fs:=flag.NewFlagSet("stage-pair",flag.ExitOnError)
  manifest:=fs.String("manifest","","frozen pair manifest JSON")
  inbox:=fs.String("inbox","","local arm inbox")
  destination:=fs.String("destination","","owner-only local staging root")
  _=fs.Parse(os.Args[2:])
  if *manifest==""||*inbox==""||*destination==""{fmt.Fprintln(os.Stderr,"manifest, inbox and destination required");os.Exit(2)}
  result,err:=stagePair(*manifest,*inbox,*destination)
  if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
  _=emit(result)
 case "verify-receipt":
  flags:=flag.NewFlagSet("verify-receipt",flag.ExitOnError)
  r:=flags.String("receipt","","sanitized receipt JSON")
  c:=flags.String("ciphertext","","sealed result.age")
  expectedRun:=flags.String("run-id","","expected trusted native Actions run ID")
  expectedArm:=flags.String("arm","","expected isolated arm: reference or cpe")
  _=flags.Parse(os.Args[2:])
  if *r==""||*c==""{os.Exit(2)}
  v,err:=verifyBound(*r,*c,*expectedRun,*expectedArm);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(2)}
  _=emit(v)
 default:fmt.Fprintln(os.Stderr,"unsupported command");os.Exit(2)
 }
}
