//go:build linux

package main

// Descriptor-pinned, bounded ingestion for public synthetic GHA arm, packet,
// answer and verdict JSON. This verifies LOCAL file stability, not origin,
// GitHub run identity, owner admission, provider attestation or declassification.
import (
 "crypto/sha256"
 "errors"
 "io"
 "os"
 "path/filepath"
 "syscall"
)

func readPinnedArtifactJSON(path string,limit int64)([]byte,error) {
 if limit<1||limit>65536{return nil,errors.New("invalid public JSON input bound")}
 abs,err:=filepath.Abs(path)
 if err!=nil{return nil,err}
 root,rootInfo,err:=openPinnedProjectionRoot(filepath.Dir(abs))
 if err!=nil{return nil,err}
 defer root.Close()
 name:=filepath.Base(abs)
 if name==""||name=="."||name==".."{return nil,errors.New("invalid artifact leaf")}
 fd,err:=syscall.Openat(int(root.Fd()),name,
  syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,errors.New("unsafe artifact file open")}
 file:=os.NewFile(uintptr(fd),name)
 defer file.Close()
 first,err:=file.Stat()
 if err!=nil{return nil,err}
 stat,ok:=first.Sys().(*syscall.Stat_t)
 if !ok||!first.Mode().IsRegular()||stat.Nlink!=1||first.Size()<1||first.Size()>limit{
  return nil,errors.New("untrusted artifact type, hardlink or size")
 }
 check,err:=os.Lstat(abs)
 if err!=nil||!check.Mode().IsRegular()||!os.SameFile(first,check){
  return nil,errors.New("artifact changed between open and first check")
 }
 buf,err:=io.ReadAll(io.LimitReader(file,first.Size()+1))
 if err!=nil||int64(len(buf))!=first.Size(){return nil,errors.New("artifact length changed during read")}
 h:=sha256.New()
 n,err:=io.Copy(h,io.NewSectionReader(file,0,first.Size()+1))
 if err!=nil||n!=first.Size(){return nil,errors.New("artifact changed during independent digest")}
 observed:=sha256.Sum256(buf)
 if got:=h.Sum(nil);!equalSHA256(got,observed){return nil,errors.New("artifact content changed during read")}
 last,err:=file.Stat()
 if err!=nil{return nil,err}
 finalStat,ok:=last.Sys().(*syscall.Stat_t)
 if !ok||stat.Dev!=finalStat.Dev||stat.Ino!=finalStat.Ino||finalStat.Nlink!=1||
  first.Size()!=last.Size()||stat.Mtim!=finalStat.Mtim||stat.Ctim!=finalStat.Ctim{
  return nil,errors.New("artifact inode changed during read")
 }
 check,err=os.Lstat(abs)
 if err!=nil||!check.Mode().IsRegular()||!os.SameFile(last,check){
  return nil,errors.New("artifact pathname changed during read")
 }
 if err=verifyPinnedProjectionRoot(filepath.Dir(abs),root,rootInfo);err!=nil{return nil,err}
 return buf,nil
}

func equalSHA256(input []byte,expected [sha256.Size]byte)bool{
 if len(input)!=sha256.Size{return false}
 var diff byte
 for i,b:=range input {diff|=b^expected[i]}
 return diff==0
}
