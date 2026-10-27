package main

import (
 "os"
 "path/filepath"
 "sync"
 "testing"
)

func TestStagePairNewAndReplayNoOverwrite(t *testing.T){
 manifest,inbox,plan:=pairedFixture(t)
 root:=filepath.Join(t.TempDir(),"sealed-only")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 one,err:=stagePair(manifest,inbox,root)
 if err!=nil{t.Fatal(err)}
 if one.State!="CIPHERTEXT_ONLY_NOT_INGESTED"||one.AssignmentID!=plan.AssignmentID{t.Fatalf("bad stage %+v",one)}
 dest:=filepath.Join(root,plan.AssignmentID+"--"+plan.RunID+"--"+plan.RunAttempt)
 for _,name:=range []string{"manifest.json","reference/receipt.json","reference/result.age","cpe/receipt.json","cpe/result.age"}{
  file:=filepath.Join(dest,name)
  stat,err:=os.Lstat(file);if err!=nil{t.Fatal(err)}
  if !stat.Mode().IsRegular()||stat.Mode().Perm()!=0600{t.Fatalf("file %s has unsafe mode %v",name,stat.Mode())}
 }
 two,err:=stagePair(manifest,inbox,root)
 if err!=nil||two.State!="IDEMPOTENT_CIPHERTEXT_ALREADY_STAGED"{t.Fatalf("replay %+v %v",two,err)}
 items,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
 if len(items)!=1{t.Fatalf("partial or duplicate stages: %d",len(items))}
}
func TestStageRejectsConflictingReplay(t *testing.T){
 manifest,inbox,plan:=pairedFixture(t)
 root:=filepath.Join(t.TempDir(),"private")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 if _,err:=stagePair(manifest,inbox,root);err!=nil{t.Fatal(err)}
 target:=filepath.Join(root,plan.AssignmentID+"--"+plan.RunID+"--"+plan.RunAttempt)
 file:=filepath.Join(target,"cpe","result.age")
 if err:=os.WriteFile(file,[]byte("corrupted retained ciphertext"),0600);err!=nil{t.Fatal(err)}
 if _,err:=stagePair(manifest,inbox,root);err==nil{t.Fatal("conflicting retained ciphertext accepted")}
}
func TestStageRejectsUnauthorizedInputAndDestination(t *testing.T){
 cases:=[]struct{name string;mutate func(t *testing.T,manifest,inbox,root string)}{
  {"loose-root",func(t *testing.T,m,inbox,root string){if e:=os.Chmod(root,0755);e!=nil{t.Fatal(e)}}},
  {"tampered-input",func(t *testing.T,m,inbox,root string){if e:=os.WriteFile(filepath.Join(inbox,"cpe","receipt.json"),[]byte("{}"),0600);e!=nil{t.Fatal(e)}}},
  {"missing-arm",func(t *testing.T,m,inbox,root string){if e:=os.Remove(filepath.Join(inbox,"reference","result.age"));e!=nil{t.Fatal(e)}}},
  {"symlinked-input",func(t *testing.T,m,inbox,root string){
   p:=filepath.Join(inbox,"cpe","result.age");copy:=p+"-original"
   if e:=os.Rename(p,copy);e!=nil{t.Fatal(e)}
   if e:=os.Symlink(copy,p);e!=nil{t.Fatal(e)}
  }},
  {"target-occupied-by-file",func(t *testing.T,m,inbox,root string){
   p,e:=readPairPlan(m);if e!=nil{t.Fatal(e)}
   name:=p.AssignmentID+"--"+p.RunID+"--"+p.RunAttempt
   if e:=os.WriteFile(filepath.Join(root,name),[]byte("occupied"),0600);e!=nil{t.Fatal(e)}
  }},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   m,inbox,_:=pairedFixture(t)
   root:=filepath.Join(t.TempDir(),"private")
   if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
   tc.mutate(t,m,inbox,root)
   if _,err:=stagePair(m,inbox,root);err==nil{t.Fatal("untrusted staging input accepted")}
  })
 }
}

func TestStagePairConcurrentIdenticalRequestsRemainSingleCommit(t *testing.T){
 manifest,inbox,plan:=pairedFixture(t)
 root:=filepath.Join(t.TempDir(),"private")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 var wg sync.WaitGroup
 results:=make(chan error,6)
 for i:=0;i<6;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   _,err:=stagePair(manifest,inbox,root)
   results<-err
  }()
 }
 wg.Wait()
 close(results)
 for err:=range results{if err!=nil{t.Fatalf("concurrent identical stage failed: %v",err)}}
 entries,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)}
 if len(entries)!=1 || entries[0].Name()!=plan.AssignmentID+"--"+plan.RunID+"--"+plan.RunAttempt {
  t.Fatalf("non-idempotent concurrent result: %+v",entries)
 }
}
func TestStagePairExistingSymlinkTargetDenied(t *testing.T){
 manifest,inbox,plan:=pairedFixture(t)
 root:=filepath.Join(t.TempDir(),"private")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 another:=filepath.Join(t.TempDir(),"other")
 if err:=os.Mkdir(another,0700);err!=nil{t.Fatal(err)}
 target:=filepath.Join(root,plan.AssignmentID+"--"+plan.RunID+"--"+plan.RunAttempt)
 if err:=os.Symlink(another,target);err!=nil{t.Fatal(err)}
 if _,err:=stagePair(manifest,inbox,root);err==nil{t.Fatal("symlink target admitted")}
}
