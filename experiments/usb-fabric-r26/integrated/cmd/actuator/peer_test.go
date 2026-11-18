package main

import (
 "errors"
 "net"
 "os"
 "path/filepath"
 "testing"
)

func TestRealLinuxUnixPeerCredentialsAndWrongUIDFailClosed(t *testing.T){
 path:=filepath.Join(t.TempDir(),"controller.sock")
 ln,err:=net.Listen("unix",path);if err!=nil{t.Fatal(err)}
 defer ln.Close()
 if err=os.Chmod(path,0600);err!=nil{t.Fatal(err)}
 conn,err:=net.Dial("unix",path);if err!=nil{t.Fatal(err)}
 defer conn.Close()
 accepted,err:=ln.Accept();if err!=nil{t.Fatal(err)}
 defer accepted.Close()
 id,err:=kernelPeer(accepted);if err!=nil{t.Fatal(err)}
 if id.PID<=1||id.UID!=uint32(os.Geteuid()){
  t.Fatalf("kernel peer identity mismatch %+v",id)
 }
 if err:=authorizePeer(accepted,os.Geteuid());err!=nil{t.Fatal(err)}
 denied:=os.Geteuid()+1
 if err:=authorizePeer(accepted,denied);!errors.Is(err,ErrPeerDenied){
  t.Fatalf("wrong actual OS UID was accepted: %v",err)
 }
 a,b:=net.Pipe();defer a.Close();defer b.Close()
 if err:=authorizePeer(a,os.Geteuid());!errors.Is(err,ErrPeerDenied){
  t.Fatalf("non-Unix socket accepted: %v",err)
 }
 if err:=authorizePeer(nil,os.Geteuid());!errors.Is(err,ErrPeerDenied){
  t.Fatalf("nil socket accepted: %v",err)
 }
 t.Log("R27_REAL_UNIX_SO_PEERCRED_TRUST_AND_WRONG_UID_DENIED=PASS")
}
