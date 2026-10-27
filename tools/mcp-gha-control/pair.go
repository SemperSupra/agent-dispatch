package main

// Read-only paired-arm preflight. Its caller must separately attest that the
// supplied manifest was issued by the trusted private dispatch authority and
// verify the native GitHub jobs/artifact IDs. No plaintext or keys are opened.
import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)
type PairArm struct {
 Arm string `json:"arm"`
 JobID string `json:"job_id"`
 ArtifactID string `json:"artifact_id"`
 PlanSHA256 string `json:"plan_sha256"`
 ReceiptSHA256 string `json:"receipt_sha256"`
}
type PairPlan struct {
 Schema string `json:"schema"`
 AssignmentID string `json:"assignment_id"`
 Repository string `json:"repository"`
 Workflow string `json:"workflow"`
 RunID string `json:"run_id"`
 RunAttempt string `json:"run_attempt"`
 SourceSHA string `json:"source_sha"`
 WorkflowSourceSHA string `json:"workflow_source_sha,omitempty"`
 ProviderImageDigest string `json:"provider_image_digest"`
 ConfigSHA256 string `json:"config_sha256"`
 Arms []PairArm `json:"arms"`
}
type PairPreflight struct {
 Schema string `json:"schema"`
 AssignmentID string `json:"assignment_id"`
 RunID string `json:"run_id"`
 RunAttempt string `json:"run_attempt"`
 SourceSHA string `json:"source_sha"`
 ArmCount int `json:"arm_count"`
 CiphertextAndReceiptsMatch bool `json:"ciphertext_and_receipts_match"`
 State string `json:"state"`
 OriginState string `json:"origin_state"`
 ScienceState string `json:"science_state"`
}
func readPairPlan(path string)(PairPlan,error){
 var p PairPlan
 f,e:=os.Open(path);if e!=nil{return p,e};defer f.Close()
 b,e:=readBounded(f,32768);if e!=nil{return p,e}
 dec:=json.NewDecoder(strings.NewReader(string(b)));dec.DisallowUnknownFields()
 if e=dec.Decode(&p);e!=nil{return p,e}
 var extra any
 if e=dec.Decode(&extra);e!=io.EOF{return p,errors.New("trailing manifest JSON")}
 return p,nil
}
const qualificationWorkflow = ".github/workflows/mcp-gha-artifact-lifecycle-qualification.yml"
const syntheticCollectorSource = "330c65f4701a3a1e9aa25ad4dc60d06c1477a4fa"
func validatePairPlan(p PairPlan)error{
 sourceContractOK:=false
 switch p.Schema {
 case "mcp-gha-private-pair-preflight/v1":
  sourceContractOK=p.Workflow==workflow&&p.WorkflowSourceSHA==""
 case "mcp-gha-private-pair-preflight/v2":
  // Deliberately narrow: public synthetic transport only. No other
  // composite-source executions are admitted or scientifically trusted.
  sourceContractOK=p.Workflow==qualificationWorkflow&&hex40.MatchString(p.WorkflowSourceSHA)&&p.SourceSHA==syntheticCollectorSource
 }
 if !sourceContractOK||p.Repository!=repo||
 !digits.MatchString(p.RunID)||!digits.MatchString(p.RunAttempt)||!hex40.MatchString(p.SourceSHA)||
 !pinnedSearxImage.MatchString(p.ProviderImageDigest)||!hex64.MatchString(p.ConfigSHA256)||
 len(p.AssignmentID)<3||len(p.AssignmentID)>96||len(p.Arms)!=2 {
  return errors.New("unadmitted pair manifest")
 }
 for _,r:=range p.AssignmentID{
  if !(r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='.'||r=='_'||r=='-'){
   return errors.New("unsafe assignment ID")
  }
 }
 seenArm:=map[string]bool{};seenJob:=map[string]bool{};seenArtifact:=map[string]bool{}
 for _,a:=range p.Arms{
  if a.Arm!="reference"&&a.Arm!="cpe"{return errors.New("invalid pair arm")}
  if seenArm[a.Arm]||!digits.MatchString(a.JobID)||seenJob[a.JobID]||
  !digits.MatchString(a.ArtifactID)||seenArtifact[a.ArtifactID]||
  !hex64.MatchString(a.PlanSHA256)||!hex64.MatchString(a.ReceiptSHA256) {
   return errors.New("duplicated/missing native arm, job or artifact identity")
  }
  seenArm[a.Arm]=true;seenJob[a.JobID]=true;seenArtifact[a.ArtifactID]=true
 }
 if !seenArm["reference"]||!seenArm["cpe"]{return errors.New("both tracks required")}
 if p.Arms[0].PlanSHA256==p.Arms[1].PlanSHA256{return errors.New("identical arm plan hashes")}
 return nil
}
func noSymlinkFile(path string)error{
 info,e:=os.Lstat(path)
 if e!=nil{return e}
 if !info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0{return errors.New("non-regular/symlink input denied")}
 return nil
}
func pairPreflight(manifest,inbox string)(PairPreflight,error){
 var out PairPreflight
 if e:=noSymlinkFile(manifest);e!=nil{return out,e}
 p,e:=readPairPlan(manifest);if e!=nil{return out,e}
 if e=validatePairPlan(p);e!=nil{return out,e}
 root,e:=filepath.Abs(inbox);if e!=nil{return out,e}
 info,e:=os.Lstat(root);if e!=nil{return out,e}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return out,errors.New("inbox must be a real directory")}
 cipherSeen:=map[string]bool{}
 for _,a:=range p.Arms{
  dir:=filepath.Join(root,a.Arm)
  stat,e:=os.Lstat(dir);if e!=nil{return out,e}
  if !stat.IsDir()||stat.Mode()&os.ModeSymlink!=0{return out,errors.New("arm path must be directory")}
  rfile:=filepath.Join(dir,"receipt.json")
  cfile:=filepath.Join(dir,"result.age")
  if e=noSymlinkFile(rfile);e!=nil{return out,e}
  if e=noSymlinkFile(cfile);e!=nil{return out,e}
  rbytes,e:=os.ReadFile(rfile);if e!=nil{return out,e}
  if len(rbytes)>32768{return out,errors.New("receipt too large")}
  rdigest:=sha256.Sum256(rbytes)
  if hex.EncodeToString(rdigest[:])!=a.ReceiptSHA256{return out,fmt.Errorf("%s receipt digest conflicts with precommitted manifest",a.Arm)}
  v,e:=verifyBound(rfile,cfile,p.RunID,a.Arm)
  if e!=nil{return out,fmt.Errorf("%s: %w",a.Arm,e)}
  r,e:=loadReceipt(rfile);if e!=nil{return out,e}
  if r.SourceSHA!=p.SourceSHA||r.RunAttempt!=p.RunAttempt||
  r.PlanSHA256!=a.PlanSHA256||
  r.ProviderImageDigest!=p.ProviderImageDigest||
  r.ConfigSHA256!=p.ConfigSHA256||
  v.ScienceState!="SYNTHETIC_ONLY_NO_CPE_AUTHORITY_OR_ADJUDICATION"{
   return out,fmt.Errorf("%s source/projection origin or science state mismatch",a.Arm)
  }
  if cipherSeen[r.CiphertextSHA256]{return out,errors.New("identical ciphertext for both arms")}
  cipherSeen[r.CiphertextSHA256]=true
 }
 return PairPreflight{
  Schema:"mcp-gha-private-pair-preflight-result/v1",
  AssignmentID:p.AssignmentID,RunID:p.RunID,RunAttempt:p.RunAttempt,
  SourceSHA:p.SourceSHA,ArmCount:2,CiphertextAndReceiptsMatch:true,
  State:"PAIR_LOCAL_BYTE_CONSISTENCY_ONLY",
  OriginState:"UNATTESTED_MANIFEST_NATIVE_JOB_AND_ARTIFACT_IDS",
  ScienceState:"SYNTHETIC_ONLY_NOT_BLIND_CPE",
 },nil
}
