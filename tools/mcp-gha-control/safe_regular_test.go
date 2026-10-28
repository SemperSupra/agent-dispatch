package main

import (
 "crypto/sha256"
 "errors"
 "io"
 "os"
 "path/filepath"
 "syscall"
 "testing"
)

func TestPinnedRegularNormalHashAndCopy(t *testing.T){
 dir:=t.TempDir();path:=filepath.Join(dir,"receipt.json")
 payload:=[]byte("bounded public synthetic test")
 if err:=os.WriteFile(path,payload,0600);err!=nil{t.Fatal(err)}
 f,info,err:=openPinnedRegular(path,32768)
 if err!=nil{t.Fatal(err)}
 defer f.Close()
 h:=sha256.New()
 n,err:=copyPinnedBytes(h,f,info)
 if err!=nil||n!=int64(len(payload)){t.Fatalf("read: n=%d err=%v",n,err)}
 if err:=pinnedFileUnchanged(path,f,info);err!=nil{t.Fatal(err)}
}
func TestPinnedRegularRejectsSymlinkFIFOHardlinkAndLargeFile(t *testing.T){
 dir:=t.TempDir()
 source:=filepath.Join(dir,"plain")
 if err:=os.WriteFile(source,[]byte("safe"),0600);err!=nil{t.Fatal(err)}
 hard:=filepath.Join(dir,"hard")
 if err:=os.Link(source,hard);err!=nil{t.Fatal(err)}
 if f,_,err:=openPinnedRegular(source,32768);err==nil{f.Close();t.Fatal("hardlinked input accepted")}
 if err:=os.Remove(hard);err!=nil{t.Fatal(err)}
 link:=filepath.Join(dir,"link")
 if err:=os.Symlink(source,link);err!=nil{t.Fatal(err)}
 if f,_,err:=openPinnedRegular(link,32768);err==nil{f.Close();t.Fatal("symlink input accepted")}
 fifo:=filepath.Join(dir,"fifo")
 if err:=syscall.Mkfifo(fifo,0600);err!=nil{t.Fatal(err)}
 // O_NONBLOCK must not hang waiting for FIFO writer.
 if f,_,err:=openPinnedRegular(fifo,32768);err==nil{f.Close();t.Fatal("FIFO input accepted")}
 big:=filepath.Join(dir,"big")
 if err:=os.WriteFile(big,make([]byte,4096),0600);err!=nil{t.Fatal(err)}
 if f,_,err:=openPinnedRegular(big,32);err==nil{f.Close();t.Fatal("oversized input accepted")}
}
func TestPinnedRegularDetectsPathSwapAndChangedInode(t *testing.T){
 dir:=t.TempDir()
 for _,mode:=range []string{"replace-path","append","same-size-edit"}{
  t.Run(mode,func(t *testing.T){
   path:=filepath.Join(dir,mode+".age")
   if err:=os.WriteFile(path,[]byte("original text"),0600);err!=nil{t.Fatal(err)}
   f,info,err:=openPinnedRegular(path,32768)
   if err!=nil{t.Fatal(err)}
   defer f.Close()
   switch mode{
   case "replace-path":
    prior:=path+".prior"
    if err:=os.Rename(path,prior);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(path,[]byte("other content"),0600);err!=nil{t.Fatal(err)}
   case "append":
    fd,err:=os.OpenFile(path,os.O_WRONLY|os.O_APPEND,0600);if err!=nil{t.Fatal(err)}
    if _,err=fd.Write([]byte(" additional"));err!=nil{t.Fatal(err)}
    _=fd.Close()
   case "same-size-edit":
    fd,err:=os.OpenFile(path,os.O_WRONLY,0600);if err!=nil{t.Fatal(err)}
    if _,err=fd.WriteAt([]byte("XXXXXXXXXXXXX"),0);err!=nil{t.Fatal(err)}
    _=fd.Close()
   }
   if err:=pinnedFileUnchanged(path,f,info);err==nil{t.Fatal("modified file identity accepted")}
  })
 }
}
func TestPinnedCopyRejectsPathChangeAfterRead(t *testing.T){
 dir:=t.TempDir()
 source:=filepath.Join(dir,"packet")
 if err:=os.WriteFile(source,[]byte("data"),0600);err!=nil{t.Fatal(err)}
 f,info,err:=openPinnedRegular(source,32768);if err!=nil{t.Fatal(err)}
 defer f.Close()
 if _,err:=copyPinnedBytes(io.Discard,f,info);err!=nil{t.Fatal(err)}
 if err:=os.Remove(source);err!=nil{t.Fatal(err)}
 if err:=pinnedFileUnchanged(source,f,info);err==nil{t.Fatal("disappeared source accepted")}
}
var _ = errors.Is
