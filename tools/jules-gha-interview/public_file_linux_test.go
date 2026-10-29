//go:build linux

package main

import (
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "syscall"
 "testing"
)

func TestMembranePinnedSyntheticFileCases(t *testing.T) {
 const rel="src/fixture.txt"
 makeCase:=func(t *testing.T)(string,ProjectionFile,string){
  t.Helper()
  root:=t.TempDir()
  if e:=os.Mkdir(filepath.Join(root,"src"),0700);e!=nil{t.Fatal(e)}
  path:=filepath.Join(root,rel)
  data:=[]byte("public synthetic signed fixture only\n")
  if e:=os.WriteFile(path,data,0600);e!=nil{t.Fatal(e)}
  hash:=sha256.Sum256(data)
  return root,ProjectionFile{Path:rel,Class:"V1",Size:int64(len(data)),SHA256:hex.EncodeToString(hash[:])},path
 }
 t.Run("valid",func(t *testing.T){
  root,file,_:=makeCase(t)
  if e:=verifyPinnedProjectionFile(root,rel,file);e!=nil{t.Fatal(e)}
 })
 t.Run("empty-file-valid",func(t *testing.T){
  root,file,path:=makeCase(t)
  if e:=os.WriteFile(path,nil,0600);e!=nil{t.Fatal(e)}
  empty:=sha256.Sum256(nil);file.SHA256=hex.EncodeToString(empty[:]);file.Size=0
  if e:=verifyPinnedProjectionFile(root,rel,file);e!=nil{t.Fatal(e)}
 })
 t.Run("same-size-bytes-changed",func(t *testing.T){
  root,file,path:=makeCase(t)
  data:=[]byte("public synthetic signed fixture only\n")
  data[0]='x'
  if e:=os.WriteFile(path,data,0600);e!=nil{t.Fatal(e)}
  if e:=verifyPinnedProjectionFile(root,rel,file);e==nil{t.Fatal("modified same-size bytes accepted")}
 })
 t.Run("hardlink",func(t *testing.T){
  root,file,path:=makeCase(t)
  if e:=os.Link(path,filepath.Join(root,"alias"));e!=nil{t.Fatal(e)}
  if e:=verifyPinnedProjectionFile(root,rel,file);e==nil{t.Fatal("hardlink accepted")}
 })
 t.Run("symlink-leaf",func(t *testing.T){
  root,file,path:=makeCase(t)
  if e:=os.Rename(path,path+".actual");e!=nil{t.Fatal(e)}
  if e:=os.Symlink(filepath.Base(path)+".actual",path);e!=nil{t.Fatal(e)}
  if e:=verifyPinnedProjectionFile(root,rel,file);e==nil{t.Fatal("symlink leaf accepted")}
 })
 t.Run("symlink-ancestor",func(t *testing.T){
  root,file,_:=makeCase(t)
  if e:=os.Rename(filepath.Join(root,"src"),filepath.Join(root,"actual"));e!=nil{t.Fatal(e)}
  if e:=os.Symlink("actual",filepath.Join(root,"src"));e!=nil{t.Fatal(e)}
  if e:=verifyPinnedProjectionFile(root,rel,file);e==nil{t.Fatal("symlink ancestor accepted")}
 })
 t.Run("fifo-no-block",func(t *testing.T){
  root,file,path:=makeCase(t)
  if e:=os.Remove(path);e!=nil{t.Fatal(e)}
  if e:=syscall.Mkfifo(path,0600);e!=nil{t.Fatal(e)}
  if e:=verifyPinnedProjectionFile(root,rel,file);e==nil{t.Fatal("FIFO accepted")}
 })
}
