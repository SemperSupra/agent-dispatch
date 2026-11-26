//go:build linux

package main

import (
 "encoding/json"
 "errors"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "syscall"
 "testing"
 "time"
)

// A real kernel Unix socket connects two monitors to the same peer PID.
// The second owner must be denied before its first protocol command.
func TestOwnerFencePrecedesNegotiation(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"q.sock")
 l,err:=net.Listen("unix",path)
 if err!=nil{t.Fatal(err)}
 defer l.Close()
 type witness struct { command string; err error }
 observed:=make(chan witness,2)
 serve:=func(){
  c,e:=l.Accept()
  if e!=nil{observed<-witness{err:e};return}
  defer c.Close()
  _=c.SetDeadline(time.Now().Add(3*time.Second))
  _=json.NewEncoder(c).Encode(map[string]any{"QMP":map[string]any{}})
  var req map[string]any
  e=json.NewDecoder(c).Decode(&req)
  command,_:=req["execute"].(string)
  if e==nil{_=json.NewEncoder(c).Encode(map[string]any{"return":map[string]any{}})}
  observed<-witness{command,e}
 }
 go serve()
 q,err:=connectQMP(path)
 if err!=nil{t.Fatal(err)}
 defer q.conn.Close()
 first,err:=claimAndNegotiateQMP(q)
 if err!=nil{t.Fatal(err)}
 defer first.Close()
 if w:=<-observed;w.err!=nil||w.command!="qmp_capabilities"{t.Fatalf("first negotiation: %+v",w)}
 go serve()
 q2,err:=connectQMP(path)
 if err!=nil{t.Fatal(err)}
 denied,err:=claimAndNegotiateQMP(q2)
 _=q2.conn.Close()
 if denied!=nil{_=denied.Close();t.Fatal("second owner acquired")}
 if !errors.Is(err,syscall.EWOULDBLOCK){t.Fatalf("wanted busy, got %v",err)}
 if w:=<-observed;w.err==nil||w.command!=""{t.Fatalf("denied owner issued command: %+v",w)}
 t.Log("OWNER_BEFORE_QMP_CAPABILITIES_REAL_UNIX=PASS")
}

func TestFailedGreetingReleasesOwner(t *testing.T){
 path:=filepath.Join(t.TempDir(),"q.sock")
 l,err:=net.Listen("unix",path)
 if err!=nil{t.Fatal(err)}
 defer l.Close()
 go func(){
  c,e:=l.Accept()
  if e!=nil{return}
  defer c.Close()
  _=json.NewEncoder(c).Encode(map[string]any{"invalid":true})
 }()
 q,err:=connectQMP(path)
 if err!=nil{t.Fatal(err)}
 defer q.conn.Close()
 o,err:=claimAndNegotiateQMP(q)
 if o!=nil{_=o.Close();t.Fatal("malformed greeting admitted")}
 if err==nil{t.Fatal("missing greeting accepted")}
 retry,err:=acquireVMOwner(q.conn)
 if err!=nil{t.Fatalf("failed negotiation retained owner: %v",err)}
 _=retry.Close()
}

// This optional separate live test exercises actual QEMU TCG, not guest HID.
func TestLiveQEMUOwnerBeforeNegotiation(t *testing.T){
 if os.Getenv("USB_NATIVE_QEMU_LIVE")!="1"{t.Skip("live QEMU lane not requested")}
 exe,err:=exec.LookPath("qemu-system-x86_64")
 if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 a,b:=filepath.Join(dir,"a.sock"),filepath.Join(dir,"b.sock")
 cmd:=exec.Command(exe,"-machine","q35,accel=tcg","-m","128","-nodefaults","-display","none","-S","-qmp","unix:"+a+",server=on,wait=off","-qmp","unix:"+b+",server=on,wait=off")
 if err=cmd.Start();err!=nil{t.Fatal(err)}
 defer func(){_=cmd.Process.Kill();_=cmd.Wait()}()
 q,err:=connectQMP(a)
 if err!=nil{t.Fatal(err)}
 defer q.conn.Close()
 o,err:=claimAndNegotiateQMP(q)
 if err!=nil{t.Fatal(err)}
 defer o.Close()
 if pristine,e:=q.prelaunchOnly();e!=nil||!pristine{t.Fatalf("real QMP prelaunch: %v %v",pristine,e)}
 q2,err:=connectQMP(b)
 if err!=nil{t.Fatal(err)}
 defer q2.conn.Close()
 other,err:=claimAndNegotiateQMP(q2)
 if other!=nil{_=other.Close();t.Fatal("second QEMU owner acquired")}
 if !errors.Is(err,syscall.EWOULDBLOCK){t.Fatalf("expected owner busy: %v",err)}
 t.Log("OWNER_BEFORE_QMP_CAPABILITIES_REAL_QEMU_TCG=PASS")
}
