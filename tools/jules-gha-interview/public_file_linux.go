//go:build linux

package main

// Public synthetic verifier file custody: O_NOFOLLOW on each path component,
// bounded regular-file reads and a second digest guard against same-size edits.
// This verifies signed BYTES only; it is not trusted source-release authority.
// A controller must independently freeze/protect the tree before publication.
import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "io"
 "os"
 "path/filepath"
 "strings"
 "syscall"
)

// openPinnedProjectionRoot refuses symlink ancestors in the absolute root
// path, pins the root directory inode and returns its initial identity.
// This does not make an otherwise mutable directory tree an atomic snapshot.
func openPinnedProjectionRoot(root string) (*os.File,os.FileInfo,error) {
 abs,err:=filepath.Abs(root)
 if err!=nil{return nil,nil,err}
 cur,err:=syscall.Open("/",syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,nil,errors.New("projected root ancestor unavailable")}
 for _,part:=range strings.Split(strings.TrimPrefix(abs,"/"),"/") {
  if part==""{continue}
  if part=="."||part==".."{
   _ = syscall.Close(cur)
   return nil,nil,errors.New("projected root contains traversing ancestor")
  }
  next,e:=syscall.Openat(cur,part,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
  _ = syscall.Close(cur)
  if e!=nil{return nil,nil,errors.New("projected root contains unsafe ancestor")}
  cur=next
 }
 handle:=os.NewFile(uintptr(cur),abs)
 info,err:=handle.Stat()
 if err!=nil||!info.IsDir(){handle.Close();return nil,nil,errors.New("projected root not a real directory")}
 observed,err:=os.Lstat(abs)
 if err!=nil||!observed.IsDir()||!os.SameFile(info,observed){
  handle.Close();return nil,nil,errors.New("projected root differs from pinned inode")
 }
 return handle,info,nil
}

func verifyPinnedProjectionRoot(root string,handle *os.File,original os.FileInfo) error {
 after,err:=handle.Stat()
 if err!=nil||!os.SameFile(original,after)||!after.IsDir(){
  return errors.New("projected root inode changed during verification")
 }
 current,err:=os.Lstat(root)
 if err!=nil||!current.IsDir()||!os.SameFile(after,current){
  return errors.New("projected root path replaced during verification")
 }
 return nil
}

func verifyPinnedProjectionFile(root, relative string, expected ProjectionFile) error {
 parts:=strings.Split(relative,"/")
 if len(parts)==0 {return errors.New("empty projected path")}
 rootFile,_,err:=openPinnedProjectionRoot(root)
 if err!=nil{return err}
 defer rootFile.Close()
 rootFD:=int(rootFile.Fd())
 current:=rootFD
 defer func(){if current!=rootFD{_ = syscall.Close(current)}}()
 for i,part:=range parts[:len(parts)-1]{
  _ = i
  if part==""||part=="."||part==".." {return errors.New("untrusted directory component")}
  next,e:=syscall.Openat(current,part,syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
  if e!=nil{return errors.New("unsafe projected ancestor")}
  if current!=rootFD{_ = syscall.Close(current)}
  current=next
 }
 leaf:=parts[len(parts)-1]
 if leaf==""||leaf=="."||leaf==".." {return errors.New("untrusted projected leaf")}
 fd,err:=syscall.Openat(current,leaf,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,0)
 if err!=nil{return errors.New("unsafe projected file open")}
 f:=os.NewFile(uintptr(fd),leaf)
 defer f.Close()
 info,err:=f.Stat()
 if err!=nil{return err}
 st,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||!info.Mode().IsRegular()||st.Nlink!=1||info.Size()!=expected.Size||expected.Size<0||expected.Size>8<<20 {
  return errors.New("nonregular, linked, or incorrectly sized projected file")
 }
 path:=filepath.Join(root,relative)
 latest,err:=os.Lstat(path)
 if err!=nil||!latest.Mode().IsRegular()||!os.SameFile(info,latest) {return errors.New("projected path differs from opened file")}
 var first [sha256.Size]byte
 for pass:=0;pass<2;pass++ {
  hash:=sha256.New()
  n,e:=io.Copy(hash,io.NewSectionReader(f,0,expected.Size+1))
  if e!=nil||n!=expected.Size {return errors.New("projected file length changed during read")}
  var sum [sha256.Size]byte
  copy(sum[:],hash.Sum(nil))
  if pass==0{first=sum} else if sum!=first{return errors.New("projected file bytes changed during read")}
 }
 if hex.EncodeToString(first[:])!=expected.SHA256{return errors.New("projected file hash mismatch")}
 after,err:=f.Stat()
 if err!=nil{return err}
 newStat,ok:=after.Sys().(*syscall.Stat_t)
 if !ok||st.Dev!=newStat.Dev||st.Ino!=newStat.Ino||newStat.Nlink!=1||
  st.Size!=newStat.Size||st.Mtim!=newStat.Mtim||st.Ctim!=newStat.Ctim {
  return errors.New("projected inode changed during verification")
 }
 latest,err=os.Lstat(path)
 if err!=nil||!latest.Mode().IsRegular()||!os.SameFile(after,latest){return errors.New("projected pathname changed during verification")}
 return nil
}
