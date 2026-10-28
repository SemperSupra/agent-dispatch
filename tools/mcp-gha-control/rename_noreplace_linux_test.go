//go:build linux

package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "sync"
 "syscall"
 "testing"
)

func TestStageLinuxNoReplaceRefusesExistingEmptyDirectory(t *testing.T) {
 root:=t.TempDir()
 from:=filepath.Join(root,"pending")
 target:=filepath.Join(root,"committed")
 if err:=os.Mkdir(from,0700);err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(target,0700);err!=nil{t.Fatal(err)}
 if err:=renameDirectoryNoReplace(from,target);!errors.Is(err,syscall.EEXIST){
  t.Fatalf("empty occupied destination overwritten or wrong denial: %v",err)
 }
 if _,err:=os.Stat(from);err!=nil{t.Fatalf("pending candidate disappeared: %v",err)}
 if items,err:=os.ReadDir(target);err!=nil||len(items)!=0{t.Fatalf("occupied target altered: %v %v",items,err)}
}

func TestStageLinuxNoReplaceConcurrentDistinctSourcesExactlyOneWinner(t *testing.T){
 root:=t.TempDir()
 dest:=filepath.Join(root,"committed")
 const challengers=12
 var wg sync.WaitGroup
 errorsOut:=make(chan error,challengers)
 for n:=0;n<challengers;n++{
  dir:=filepath.Join(root,fmt.Sprintf("pending-%02d",n))
  if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(filepath.Join(dir,"winner"),[]byte(fmt.Sprint(n)),0600);err!=nil{t.Fatal(err)}
  wg.Add(1)
  go func(path string){
   defer wg.Done()
   errorsOut<-renameDirectoryNoReplace(path,dest)
  }(dir)
 }
 wg.Wait();close(errorsOut)
 successes,denials:=0,0
 for err:=range errorsOut{
  if err==nil{successes++}else if errors.Is(err,syscall.EEXIST){denials++}else{t.Fatalf("unexpected race error %v",err)}
 }
 if successes!=1||denials!=challengers-1{
  t.Fatalf("atomic no-replace not exclusive: success=%d denied=%d",successes,denials)
 }
 data,err:=os.ReadFile(filepath.Join(dest,"winner"))
 if err!=nil||len(data)==0{t.Fatalf("winner not committed: %q %v",data,err)}
}
func TestStagePairWonRaceWithHostileEmptyDirectoryMustFailClosed(t *testing.T){
 m,inbox,p:=pairedFixture(t)
 root:=filepath.Join(t.TempDir(),"store")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 occupied:=filepath.Join(root,p.AssignmentID+"--"+p.RunID+"--"+p.RunAttempt)
 if err:=os.Mkdir(occupied,0700);err!=nil{t.Fatal(err)}
 if _,err:=stagePair(m,inbox,root);err==nil{t.Fatal("preexisting empty immutable identity accepted")}
 if info,err:=os.Stat(occupied);err!=nil||!info.IsDir(){t.Fatalf("occupied dir removed: %v",err)}
}
