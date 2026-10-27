package main

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func pairedFixture(t *testing.T)(string,string,PairPlan){
 t.Helper()
 base:=t.TempDir()
 inbox:=filepath.Join(base,"inbox")
 if e:=os.MkdirAll(inbox,0700);e!=nil{t.Fatal(e)}
 arms:=[]PairArm{}
 for i,arm:=range []string{"reference","cpe"}{
  _,_,rec:=armFixture(t)
  dir:=filepath.Join(inbox,arm)
  if e:=os.Mkdir(dir,0700);e!=nil{t.Fatal(e)}
  rec.Arm=arm
  rec.RunID="40506152579"
  rec.RunAttempt="1"
  rec.SourceSHA=strings.Repeat("a",40)
  rec.PlanSHA256=strings.Repeat(string('b'+rune(i)),64)
  data:=[]byte("sealed synthetic test payload "+arm)
  ch:=sha256.Sum256(data)
  rec.CiphertextSHA256=hex.EncodeToString(ch[:])
  rec.CiphertextBytes=int64(len(data))
  if e:=os.WriteFile(filepath.Join(dir,"result.age"),data,0600);e!=nil{t.Fatal(e)}
  file:=filepath.Join(dir,"receipt.json")
  saveReceipt(t,file,rec)
  bytes,e:=os.ReadFile(file);if e!=nil{t.Fatal(e)}
  digest:=sha256.Sum256(bytes)
  arms=append(arms,PairArm{Arm:arm,JobID:[]string{"122195853224","122195853331"}[i],
   ArtifactID:[]string{"80001","80002"}[i],PlanSHA256:rec.PlanSHA256,
   ReceiptSHA256:hex.EncodeToString(digest[:])})
 }
 p:=PairPlan{Schema:"mcp-gha-private-pair-preflight/v1",
  AssignmentID:"synthetic-qualified-run-001",
  Repository:repo,Workflow:workflow,RunID:"40506152579",
  RunAttempt:"1",SourceSHA:strings.Repeat("a",40),
  ProviderImageDigest:"ghcr.io/searxng/searxng:2026.10.23-629368e40@sha256:"+strings.Repeat("c",64),
  ConfigSHA256:strings.Repeat("d",64),Arms:arms}
 m:=filepath.Join(base,"manifest.json")
 savePair(t,m,p)
 return m,inbox,p
}
func savePair(t *testing.T,path string,p PairPlan){
 t.Helper()
 b,e:=json.Marshal(p);if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(path,b,0600);e!=nil{t.Fatal(e)}
}
func TestPairPreflightBothArmsAndNoSciencePromotion(t *testing.T){
 m,inbox,p:=pairedFixture(t)
 result,e:=pairPreflight(m,inbox)
 if e!=nil{t.Fatal(e)}
 if !result.CiphertextAndReceiptsMatch||result.ArmCount!=2||
 result.RunID!=p.RunID||result.AssignmentID!=p.AssignmentID||
 result.State!="PAIR_LOCAL_BYTE_CONSISTENCY_ONLY"||
 result.OriginState!="UNATTESTED_MANIFEST_NATIVE_JOB_AND_ARTIFACT_IDS"||
 result.ScienceState!="SYNTHETIC_ONLY_NOT_BLIND_CPE"{
  t.Fatalf("unsafe or incomplete pair result %+v",result)
 }
}
func TestPairManifestIdentityNegativeCases(t *testing.T){
 changes:=[]struct{name string;change func(*PairPlan)}{
  {"wrong-repo",func(p *PairPlan){p.Repository="elsewhere/public"}},
  {"wrong-workflow",func(p *PairPlan){p.Workflow="other.yml"}},
  {"wrong-run",func(p *PairPlan){p.RunID="40506152580"}},
  {"wrong-attempt",func(p *PairPlan){p.RunAttempt="2"}},
  {"wrong-source",func(p *PairPlan){p.SourceSHA=strings.Repeat("e",40)}},
  {"source-unpinned",func(p *PairPlan){p.SourceSHA="invalid"}},
  {"missing-arm",func(p *PairPlan){p.Arms=p.Arms[:1]}},
  {"duplicate-arm",func(p *PairPlan){p.Arms[1].Arm="reference"}},
  {"duplicate-job",func(p *PairPlan){p.Arms[1].JobID=p.Arms[0].JobID}},
  {"duplicate-artifact",func(p *PairPlan){p.Arms[1].ArtifactID=p.Arms[0].ArtifactID}},
  {"wrong-plan-hash",func(p *PairPlan){p.Arms[1].PlanSHA256=strings.Repeat("f",64)}},
  {"duplicate-plan",func(p *PairPlan){p.Arms[1].PlanSHA256=p.Arms[0].PlanSHA256}},
  {"wrong-receipt-hash",func(p *PairPlan){p.Arms[0].ReceiptSHA256=strings.Repeat("f",64)}},
  {"unsafe-assignment",func(p *PairPlan){p.AssignmentID="../escape"}},
  {"invalid-image",func(p *PairPlan){p.ProviderImageDigest="sha256:123"}},
 }
 for _,tc:=range changes{t.Run(tc.name,func(t *testing.T){
  m,inbox,p:=pairedFixture(t)
  tc.change(&p)
  savePair(t,m,p)
  if _,e:=pairPreflight(m,inbox);e==nil{t.Fatal("invalid pair accepted")}
 })}
}
func TestPairPreflightRejectsBadInputsAndArmSwap(t *testing.T){
 for _,tc:=range []struct{name string;mutate func(*testing.T,string,string)}{
  {"cipher-edited",func(t *testing.T,m,inbox string){
   t.Helper();path:=filepath.Join(inbox,"cpe","result.age")
   if e:=os.WriteFile(path,[]byte("tampered"),0600);e!=nil{t.Fatal(e)}
  }},
  {"receipt-edited",func(t *testing.T,m,inbox string){
   t.Helper();path:=filepath.Join(inbox,"reference","receipt.json")
   if e:=os.WriteFile(path,[]byte("{}"),0600);e!=nil{t.Fatal(e)}
  }},
  {"cross-arm-directory-swap",func(t *testing.T,m,inbox string){
   t.Helper();a:=filepath.Join(inbox,"reference");b:=filepath.Join(inbox,"cpe")
   tmp:=filepath.Join(inbox,"temporary")
   if e:=os.Rename(a,tmp);e!=nil{t.Fatal(e)}
   if e:=os.Rename(b,a);e!=nil{t.Fatal(e)}
   if e:=os.Rename(tmp,b);e!=nil{t.Fatal(e)}
  }},
  {"symlink-receipt",func(t *testing.T,m,inbox string){
   t.Helper();path:=filepath.Join(inbox,"reference","receipt.json")
   target:=path+".original";if e:=os.Rename(path,target);e!=nil{t.Fatal(e)}
   if e:=os.Symlink(target,path);e!=nil{t.Fatal(e)}
  }},
  {"symlink-arm",func(t *testing.T,m,inbox string){
   t.Helper();a:=filepath.Join(inbox,"reference")
   target:=a+"-renamed";if e:=os.Rename(a,target);e!=nil{t.Fatal(e)}
   if e:=os.Symlink(target,a);e!=nil{t.Fatal(e)}
  }},
  {"symlink-manifest",func(t *testing.T,m,inbox string){
   t.Helper();target:=m+".original";if e:=os.Rename(m,target);e!=nil{t.Fatal(e)}
   if e:=os.Symlink(target,m);e!=nil{t.Fatal(e)}
  }},
 }{
  t.Run(tc.name,func(t *testing.T){
   m,inbox,_:=pairedFixture(t);tc.mutate(t,m,inbox)
   if _,e:=pairPreflight(m,inbox);e==nil{t.Fatal("tampered pair accepted")}
  })
 }
}
