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


// An untrusted ancestor or a replacement directory can silently redirect
// otherwise correctly signed reads unless the *whole root chain* is pinned.
func TestMembranePinnedProjectionRootParentSymlinkDenied(t *testing.T) {
 home:=t.TempDir()
 real:=filepath.Join(home,"real")
 if err:=os.Mkdir(real,0700);err!=nil{t.Fatal(err)}
 original:=filepath.Join(real,"approved")
 if err:=os.Mkdir(original,0700);err!=nil{t.Fatal(err)}
 link:=filepath.Join(home,"alias")
 if err:=os.Symlink(real,link);err!=nil{t.Fatal(err)}
 if f,_,err:=openPinnedProjectionRoot(filepath.Join(link,"approved"));err==nil{
  f.Close();t.Fatal("symlinked ancestor accepted")
 }
}

func TestMembranePinnedProjectionRootReplacementDenied(t *testing.T) {
 home:=t.TempDir()
 root:=filepath.Join(home,"approved")
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 pinned,initial,err:=openPinnedProjectionRoot(root)
 if err!=nil{t.Fatal(err)}
 defer pinned.Close()
 if err:=verifyPinnedProjectionRoot(root,pinned,initial);err!=nil{t.Fatal(err)}
 if err:=os.Rename(root,root+"-old");err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(root,0700);err!=nil{t.Fatal(err)}
 if err:=verifyPinnedProjectionRoot(root,pinned,initial);err==nil{
  t.Fatal("replaced projected root inode accepted")
 }
}
