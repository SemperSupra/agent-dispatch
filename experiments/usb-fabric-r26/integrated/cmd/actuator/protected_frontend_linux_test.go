//go:build linux

package main

import (
 "net"
 "os"
 "path/filepath"
 "testing"
)
func TestProtectedFrontendConfiguration(t *testing.T){
 read,e:=parseOperationPolicy("status,ports");if e!=nil{t.Fatal(e)}
 mutate,e:=parseOperationPolicy("status,reserve");if e!=nil{t.Fatal(e)}
 uid:=65534;if uid==os.Geteuid(){uid=65533}
 for _,c:=range []struct{pid,uid int;p operationPolicy}{{0,uid,read},{2,0,read},{2,os.Geteuid(),read},{2,uid,operationPolicy{}},{2,uid,mutate}}{
  if e=validateProtectedFrontend(c.pid,c.uid,c.p,false,"","");e==nil{t.Fatalf("unsafe configuration accepted: %+v",c)}
 }
 if e=validateProtectedFrontend(2,uid,read,false,"","");e!=nil{t.Fatal(e)}
 if e=validateProtectedFrontend(2,uid,mutate,true,"key","receipt");e!=nil{t.Fatal(e)}
}
func TestProtectedFrontendListener(t *testing.T){
 dir:=t.TempDir();path:=filepath.Join(dir,"frontend.sock")
 if e:=os.Chmod(dir,0750);e!=nil{t.Fatal(e)}
 if l,e:=listenActuatorFrontend(path,true);e==nil{_ = l.Close();t.Fatal("weak directory accepted")}
 if e:=os.Chmod(dir,0710);e!=nil{t.Fatal(e)}
 l,e:=listenActuatorFrontend(path,true);if e!=nil{t.Fatal(e)}
 info,e:=os.Lstat(path);if e!=nil||info.Mode().Perm()!=0660||info.Mode()&os.ModeSocket==0{t.Fatalf("unexpected socket mode: %v %v",info,e)}
 if duplicate,e:=listenActuatorFrontend(path,true);e==nil{_ = duplicate.Close();t.Fatal("duplicate endpoint accepted")}
 c,e:=net.Dial("unix",path);if e!=nil{t.Fatal(e)}
 _=c.Close()
 if e=l.Close();e!=nil{t.Fatal(e)}
 if _,e=os.Lstat(path);!os.IsNotExist(e){t.Fatal("socket not removed")}
}
