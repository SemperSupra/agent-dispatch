package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)
const sampleSHA="0123456789abcdef0123456789abcdef01234567"
func sample(t *testing.T)(Packet,Answer){
 t.Helper()
 r,e:=makeArm("reference",sampleSHA,"40590048518","1");if e!=nil{t.Fatal(e)}
 f,e:=makeArm("fault",sampleSHA,"40590048518","1");if e!=nil{t.Fatal(e)}
 p,e:=makePacket(r,f);if e!=nil{t.Fatal(e)};return p,mock(p)
}
func TestSyntheticIsNotNativeJules(t *testing.T){
 p,a:=sample(t)
 x:=judge(p,a,"synthetic")
 if x.Status!="SYNTHETIC_CONTRACT_PASS"||x.ProviderObserved{t.Fatal(x)}
 x=judge(p,a,"provider")
 if x.Status!="PROVIDER_ATTESTATION_REQUIRED"||x.ProviderObserved{t.Fatal(x)}
}
func TestBadAnswersFailClosed(t *testing.T){
 cases:=map[string]func(*Answer){
  "wrong-source":func(a *Answer){a.SourceSHA=strings.Repeat("a",40)},
  "wrong-run":func(a *Answer){a.RunID="111"},
  "stale-attempt":func(a *Answer){a.Attempt="2"},
  "false-green":func(a *Answer){a.Diagnosis="PASS"},
  "actuation":func(a *Answer){a.AutoDispatch=true},
  "auto-accept":func(a *Answer){a.AcceptCandidate=true},
  "merge":func(a *Answer){a.Action="MERGE"},
  "no-evidence":func(a *Answer){a.Evidence=nil},
  "duplicate-evidence":func(a *Answer){a.Evidence=[]string{"reference:BASELINE_OK","reference:BASELINE_OK"}},
  "fabricated-evidence":func(a *Answer){a.Evidence=[]string{"reference:BASELINE_OK","fault:NO_FAILURE"}},
  "bad-schema":func(a *Answer){a.Schema="unknown"},
 }
 for name,change:=range cases{t.Run(name,func(t *testing.T){
  p,a:=sample(t);change(&a);if v:=judge(p,a,"synthetic");v.Status!="REJECTED"{t.Fatal(v)}
 })}
}
func TestBadArmIdentityAndSignals(t *testing.T){
 p,_:=sample(t)
 cases:=map[string]func(*Arm){
  "wrong-source":func(a *Arm){a.SourceSHA=strings.Repeat("f",40)},
  "wrong-run":func(a *Arm){a.RunID="123"},
  "wrong-attempt":func(a *Arm){a.Attempt="4"},
  "wrong-signal":func(a *Arm){a.Signal="BASELINE_OK"},
  "false-green":func(a *Arm){a.Status="PASS"},
  "duplicate-arm":func(a *Arm){a.Arm="reference"},
 }
 for name,change:=range cases{t.Run(name,func(t *testing.T){a:=p.Fault;change(&a);if _,e:=makePacket(p.Reference,a);e==nil{t.Fatal("accepted invalid arm")}})}
}
func TestMalformedIdentity(t *testing.T){
 for _,x:=range []struct{s,r,a string}{{"abc","1","1"},{sampleSHA,"0","1"},{sampleSHA,"1","0"},{strings.ToUpper(sampleSHA),"1","1"}}{
  if _,e:=makeArm("fault",x.s,x.r,x.a);e==nil{t.Fatal(x)}
 }
}
func TestStrictJSON(t *testing.T){
 path:=filepath.Join(t.TempDir(),"test.json")
 for _,s:=range []string{`{"unapproved":true}`,`{} {}`,strings.Repeat("x",33000)}{
  if e:=os.WriteFile(path,[]byte(s),0600);e!=nil{t.Fatal(e)}
  var a Arm;if e:=read(path,&a);e==nil{t.Fatal("accepted invalid JSON")}
 }
}
func TestStandaloneCLI(t *testing.T){
 d:=t.TempDir();r:=filepath.Join(d,"r.json");f:=filepath.Join(d,"f.json");p:=filepath.Join(d,"packet.json");a:=filepath.Join(d,"answer.json");v:=filepath.Join(d,"verdict.json")
 calls:=[][]string{
  {"arm","--arm","reference","--sha",sampleSHA,"--run-id","123","--attempt","1","--out",r},
  {"arm","--arm","fault","--sha",sampleSHA,"--run-id","123","--attempt","1","--out",f},
  {"prepare","--reference",r,"--fault",f,"--out",p},
  {"mock-answer","--packet",p,"--out",a},
  {"judge","--packet",p,"--answer",a,"--out",v},
 }
 for _,call:=range calls{if e:=execute(call);e!=nil{t.Fatalf("%s: %v",call[0],e)}}
 var x Verdict;if e:=read(v,&x);e!=nil{t.Fatal(e)}
 if x.Status!="SYNTHETIC_CONTRACT_PASS"{t.Fatal(x)}
}


// The public runner's downloaded arm/packet/answer JSON must not have
// incompatible first-vs-last field interpretations. No provider is invoked.
func TestReadRejectsDuplicateAndUnicodeAliasPackets(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"untrusted.json")
 cases:=[]struct{name,raw string}{
  {"exact-duplicate",`{"schema":"public-synthetic","schema":"public-synthetic"}`},
  {"ascii-case-alias",`{"schema":"public-synthetic","Schema":"public-synthetic"}`},
  {"unicode-fold-alias",`{"schema":"public-synthetic","ſchema":"public-synthetic"}`},
  {"nested-duplicate",`{"packet":{"source_sha":"x","source_sha":"y"}}`},
  {"nested-unicode-alias",`{"packet":{"schema":"x","ſchema":"y"}}`},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
  if e:=os.WriteFile(path,[]byte(tc.raw),0600);e!=nil{t.Fatal(e)}
  var packet map[string]any
  if e:=read(path,&packet);e==nil{t.Fatal("ambiguous artifact JSON accepted")}
 })}
}
