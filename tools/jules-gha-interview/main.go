// Public-safe synthetic interview contract. No Jules API, dispatch, merge, or acceptance.
package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "regexp"
)
const armSchema="jules-gha-arm/v1"
const packetSchema="jules-gha-interview/v1"
const answerSchema="jules-gha-answer/v1"
const verdictSchema="jules-gha-verdict/v1"
var shaOK=regexp.MustCompile("^[a-f0-9]{40}$")
var numberOK=regexp.MustCompile("^[1-9][0-9]*$")

type Arm struct {
 Schema string "json:\"schema\""
 Arm string "json:\"arm\""
 SourceSHA string "json:\"source_sha\""
 RunID string "json:\"run_id\""
 Attempt string "json:\"run_attempt\""
 Status string "json:\"status\""
 Signal string "json:\"signal\""
}
type Packet struct {
 Schema string "json:\"schema\""
 SourceSHA string "json:\"source_sha\""
 RunID string "json:\"run_id\""
 Attempt string "json:\"run_attempt\""
 Reference Arm "json:\"reference\""
 Fault Arm "json:\"fault\""
 Objective string "json:\"objective\""
 Contract string "json:\"response_contract\""
}
type Answer struct {
 Schema string "json:\"schema\""
 SourceSHA string "json:\"source_sha\""
 RunID string "json:\"run_id\""
 Attempt string "json:\"run_attempt\""
 Diagnosis string "json:\"diagnosis\""
 Evidence []string "json:\"evidence\""
 Action string "json:\"action\""
 AutoDispatch bool "json:\"auto_dispatch\""
 AcceptCandidate bool "json:\"accept_candidate\""
}
type Verdict struct {
 Schema string "json:\"schema\""
 Status string "json:\"status\""
 Reason string "json:\"reason\""
 SourceSHA string "json:\"source_sha\""
 RunID string "json:\"run_id\""
 Attempt string "json:\"run_attempt\""
 ProviderObserved bool "json:\"provider_observed\""
}
func identity(sha,run,attempt string)bool{return shaOK.MatchString(sha)&&numberOK.MatchString(run)&&numberOK.MatchString(attempt)}
func makeArm(name,sha,run,attempt string)(Arm,error){
 if !identity(sha,run,attempt){return Arm{},errors.New("invalid source/run/attempt")}
 a:=Arm{Schema:armSchema,Arm:name,SourceSHA:sha,RunID:run,Attempt:attempt}
 switch name {
 case "reference":a.Status="PASS";a.Signal="BASELINE_OK"
 case "fault":a.Status="OBSERVED_FAILURE";a.Signal="SYNTHETIC_ASSERTION_MISSING"
 default:return Arm{},errors.New("unapproved arm")
 }
 return a,nil
}
func makePacket(r,f Arm)(Packet,error){
 if r.Schema!=armSchema||r.Arm!="reference"||r.Status!="PASS"||r.Signal!="BASELINE_OK"||
  f.Schema!=armSchema||f.Arm!="fault"||f.Status!="OBSERVED_FAILURE"||f.Signal!="SYNTHETIC_ASSERTION_MISSING"{
  return Packet{},errors.New("arm content mismatch")
 }
 if !identity(r.SourceSHA,r.RunID,r.Attempt)||r.SourceSHA!=f.SourceSHA||r.RunID!=f.RunID||r.Attempt!=f.Attempt{
  return Packet{},errors.New("immutable cross-arm identity mismatch")
 }
 return Packet{Schema:packetSchema,SourceSHA:r.SourceSHA,RunID:r.RunID,Attempt:r.Attempt,Reference:r,Fault:f,
  Objective:"Diagnose the controlled synthetic failure using both observations; propose a fix only, never dispatch or accept.",
  Contract:"jules-gha-answer/v1 JSON: same source_sha/run_id/run_attempt; diagnosis SYNTHETIC_ASSERTION_MISSING; evidence reference:BASELINE_OK and fault:SYNTHETIC_ASSERTION_MISSING; action PROPOSE_FIX_ONLY; auto_dispatch=false; accept_candidate=false. Independently observe a real Jules session before attributing any answer to Jules."},nil
}
func mock(p Packet)Answer{return Answer{Schema:answerSchema,SourceSHA:p.SourceSHA,RunID:p.RunID,Attempt:p.Attempt,Diagnosis:"SYNTHETIC_ASSERTION_MISSING",Evidence:[]string{"reference:BASELINE_OK","fault:SYNTHETIC_ASSERTION_MISSING"},Action:"PROPOSE_FIX_ONLY"}}
func judge(p Packet,a Answer,mode string)Verdict{
 v:=Verdict{Schema:verdictSchema,Status:"REJECTED",Reason:"INVALID_OR_UNAUTHORIZED_ANSWER",SourceSHA:p.SourceSHA,RunID:p.RunID,Attempt:p.Attempt}
 if _,err:=makePacket(p.Reference,p.Fault);err!=nil||p.Schema!=packetSchema||p.SourceSHA!=p.Reference.SourceSHA||p.RunID!=p.Reference.RunID||p.Attempt!=p.Reference.Attempt{
  v.Reason="PACKET_NOT_VERIFIED";return v
 }
 if a.Schema!=answerSchema||a.SourceSHA!=p.SourceSHA||a.RunID!=p.RunID||a.Attempt!=p.Attempt||
 a.Diagnosis!="SYNTHETIC_ASSERTION_MISSING"||a.Action!="PROPOSE_FIX_ONLY"||a.AutoDispatch||a.AcceptCandidate||len(a.Evidence)!=2{return v}
 seen:=map[string]bool{}
 for _,e:=range a.Evidence {if seen[e]{return v};seen[e]=true}
 if !seen["reference:BASELINE_OK"]||!seen["fault:SYNTHETIC_ASSERTION_MISSING"]{return v}
 if mode=="synthetic"{v.Status="SYNTHETIC_CONTRACT_PASS";v.Reason="MOCK_ONLY_NOT_JULES";return v}
 if mode=="provider"{v.Status="PROVIDER_ATTESTATION_REQUIRED";v.Reason="NO_INDEPENDENT_JULES_SESSION_OBSERVATION";return v}
 v.Reason="UNSUPPORTED_MODE";return v
}
func read(path string,to any)error{
 // A native artifact may be untrusted even when downloaded by the fixed
 // public workflow: reject symlink/FIFO/hardlink path substitution up front.
 b,e:=readPinnedArtifactJSON(path,32768);if e!=nil{return e}
 // Artifact packets and provider answers are untrusted even if downloaded by
 // a trusted workflow. Reject duplicate and Unicode simple-fold aliases
 // before encoding/json's case-insensitive struct decode selects a last value.
 if e:=rejectAmbiguousJSON(b);e!=nil{return e}
 d:=json.NewDecoder(bytes.NewReader(b));d.DisallowUnknownFields()
 if e=d.Decode(to);e!=nil{return e}
 var other any;if d.Decode(&other)!=io.EOF{return errors.New("trailing JSON")}
 return nil
}
func write(path string,v any)error{
 b,e:=json.MarshalIndent(v,"","  ");if e!=nil{return e};b=append(b,10)
 if path=="-"{_,e=os.Stdout.Write(b);return e}
 return os.WriteFile(path,b,0600)
}
func execute(args []string)error{
 if len(args)==0{return errors.New("expected arm, prepare, mock-answer, or judge")}
 f:=flag.NewFlagSet(args[0],flag.ContinueOnError);f.SetOutput(io.Discard)
 name:=f.String("arm","","");sha:=f.String("sha","","");run:=f.String("run-id","","");attempt:=f.String("attempt","","")
 reference:=f.String("reference","","");fault:=f.String("fault","","");packetPath:=f.String("packet","","")
 answerPath:=f.String("answer","","");mode:=f.String("mode","synthetic","");out:=f.String("out","-","")
 if e:=f.Parse(args[1:]);e!=nil{return e};if f.NArg()!=0{return errors.New("unexpected arguments")}
 switch args[0]{
 case "arm":a,e:=makeArm(*name,*sha,*run,*attempt);if e!=nil{return e};return write(*out,a)
 case "prepare":
  var r,z Arm;if e:=read(*reference,&r);e!=nil{return e};if e:=read(*fault,&z);e!=nil{return e}
  p,e:=makePacket(r,z);if e!=nil{return e};return write(*out,p)
 case "mock-answer":
  var p Packet;if e:=read(*packetPath,&p);e!=nil{return e}
  if _,e:=makePacket(p.Reference,p.Fault);e!=nil{return e}
  if p.Schema!=packetSchema||p.SourceSHA!=p.Reference.SourceSHA||p.RunID!=p.Reference.RunID||p.Attempt!=p.Reference.Attempt{return errors.New("packet identity mismatch")}
  return write(*out,mock(p))
 case "judge":
  if *mode!="synthetic"&&*mode!="provider"{return errors.New("unsupported mode")}
  var p Packet;var a Answer
  if e:=read(*packetPath,&p);e!=nil{return e};if e:=read(*answerPath,&a);e!=nil{return e}
  v:=judge(p,a,*mode);if e:=write(*out,v);e!=nil{return e}
  if v.Status=="REJECTED"{return fmt.Errorf("rejected: %s",v.Reason)}
  return nil
 default:return errors.New("unknown command")
 }
}
func main(){if e:=execute(os.Args[1:]);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}}
