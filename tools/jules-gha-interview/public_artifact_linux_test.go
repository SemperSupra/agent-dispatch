//go:build linux

package main

import (
 "os"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
)

func TestPublicPinnedArtifactReadSynthetic(t *testing.T){
 t.Run("valid",func(t *testing.T){
  path:=filepath.Join(t.TempDir(),"arm.json")
  b:=[]byte("{\"schema\":\"fixture\"}\n")
  if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
  got,err:=readPinnedArtifactJSON(path,32768)
  if err!=nil||string(got)!=string(b){t.Fatalf("safe input rejected: %v",err)}
  var obj map[string]any
  if err:=read(path,&obj);err!=nil{t.Fatal(err)}
 })
 t.Run("symlink-leaf",func(t *testing.T){
  home:=t.TempDir();good:=filepath.Join(home,"real.json");link:=filepath.Join(home,"arm.json")
  if err:=os.WriteFile(good,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
  if err:=os.Symlink("real.json",link);err!=nil{t.Fatal(err)}
  if _,err:=readPinnedArtifactJSON(link,32768);err==nil{t.Fatal("symlink accepted")}
 })
 t.Run("symlink-parent",func(t *testing.T){
  home:=t.TempDir();real:=filepath.Join(home,"real")
  if err:=os.Mkdir(real,0700);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(filepath.Join(real,"arm.json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
  if err:=os.Symlink("real",filepath.Join(home,"alias"));err!=nil{t.Fatal(err)}
  if _,err:=readPinnedArtifactJSON(filepath.Join(home,"alias","arm.json"),32768);err==nil{t.Fatal("symlink parent accepted")}
 })
 t.Run("hardlink",func(t *testing.T){
  home:=t.TempDir();path:=filepath.Join(home,"arm.json")
  if err:=os.WriteFile(path,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
  if err:=os.Link(path,filepath.Join(home,"copy.json"));err!=nil{t.Fatal(err)}
  if _,err:=readPinnedArtifactJSON(path,32768);err==nil{t.Fatal("hardlinked artifact accepted")}
 })
 t.Run("fifo-nonblocking",func(t *testing.T){
  path:=filepath.Join(t.TempDir(),"arm.json")
  if err:=syscall.Mkfifo(path,0600);err!=nil{t.Fatal(err)}
  if _,err:=readPinnedArtifactJSON(path,32768);err==nil{t.Fatal("FIFO accepted")}
 })
 t.Run("empty-and-oversize",func(t *testing.T){
  path:=filepath.Join(t.TempDir(),"arm.json")
  for _,data:=range [][]byte{{},[]byte(strings.Repeat("x",32769))}{
   if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
   if _,err:=readPinnedArtifactJSON(path,32768);err==nil{t.Fatal("invalid size accepted")}
  }
 })
}
