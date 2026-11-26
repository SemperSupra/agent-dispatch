//go:build linux

package main

import (
 "encoding/json"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
 "time"
)

func TestProtectedQMPPeerPinAndPath(t *testing.T){
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,"q.sock")
 l,err:=net.Listen("unix",path)
 if err!=nil{t.Fatal(err)}
 defer l.Close()
 // The incorrect PID must cause closure with no QMP command.
 done:=make(chan error,1)
 go func(){
  c,e:=l.Accept()
  if e!=nil{done<-e;return}
  defer c.Close()
  _=c.SetReadDeadline(time.Now().Add(4*time.Second))
  var msg map[string]any
  done<-json.NewDecoder(c).Decode(&msg)
 }()
 if q,e:=connectProtectedQMP(path,os.Getpid()+1);e==nil{_=q.conn.Close();t.Fatal("wrong PID admitted")}
 if e:=<-done;e==nil{t.Fatal("wrong PID sent QMP command")}
 alias:=filepath.Join(dir,"alias")
 if err=os.Symlink(path,alias);err!=nil{t.Fatal(err)}
 if q,e:=connectProtectedQMP(alias,os.Getpid());e==nil{_=q.conn.Close();t.Fatal("symlink socket admitted")}
 if err=os.Chmod(dir,0755);err!=nil{t.Fatal(err)}
 if q,e:=connectProtectedQMP(path,os.Getpid());e==nil{_=q.conn.Close();t.Fatal("nonprivate directory admitted")}
 if err=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 go func(){
  c,e:=l.Accept()
  if e!=nil{done<-e;return}
  defer c.Close()
  _=c.SetDeadline(time.Now().Add(4*time.Second))
  _=json.NewEncoder(c).Encode(map[string]any{"QMP":map[string]any{}})
  var req map[string]any
  e=json.NewDecoder(c).Decode(&req)
  if e==nil && req["execute"]=="qmp_capabilities"{e=json.NewEncoder(c).Encode(map[string]any{"return":map[string]any{}})}
  done<-e
 }()
 q,err:=connectProtectedQMP(path,os.Getpid())
 if err!=nil{t.Fatal(err)}
 defer q.conn.Close()
 o,err:=claimAndNegotiateQMP(q)
 if err!=nil{t.Fatal(err)}
 defer o.Close()
 if err=<-done;err!=nil{t.Fatal(err)}
 raw,err:=q.conn.(*net.UnixConn).SyscallConn()
 if err!=nil{t.Fatal(err)}
 var flags uintptr
 var errno syscall.Errno
 if err=raw.Control(func(fd uintptr){flags,_,errno=syscall.Syscall(syscall.SYS_FCNTL,fd,syscall.F_GETFD,0)});err!=nil||errno!=0||flags&syscall.FD_CLOEXEC==0{t.Fatalf("QMP descriptor not close-on-exec: %v %v",err,errno)}
 t.Log("PROTECTED_QMP_PID_PATH_CLOEXEC=PASS")
}

func TestLiveProtectedQMPDistinctUID(t *testing.T){
 if os.Getenv("USB_NATIVE_QEMU_LIVE")!="1"{t.Skip("live QEMU lane not requested")}
 exe,err:=exec.LookPath("qemu-system-x86_64")
 if err!=nil{t.Fatal(err)}
 dir,err:=os.MkdirTemp("","usb-protected-qmp-")
 if err!=nil{t.Fatal(err)}
 defer os.RemoveAll(dir)
 path:=filepath.Join(dir,"q.sock")
 cmd:=exec.Command(exe,"-machine","q35,accel=tcg","-m","128","-nodefaults","-display","none","-S","-qmp","unix:"+path+",server=on,wait=off")
 if err=cmd.Start();err!=nil{t.Fatal(err)}
 defer func(){_=cmd.Process.Kill();_=cmd.Wait()}()
 deadline:=time.Now().Add(10*time.Second)
 for {
  if _,e:=os.Lstat(path);e==nil{break}
  if time.Now().After(deadline){t.Fatal("QEMU socket not ready")}
  time.Sleep(20*time.Millisecond)
 }
 // Independent real distinct UID attempts a raw path connection before the
 // trusted actuator connects. No credential, privileged production host or
 // USB device is involved: this is an ephemeral public runner.
 script:="import os,socket,sys\nassert os.geteuid()==65534\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(sys.argv[1])\nexcept PermissionError:\n print('RAW_QMP_DISTINCT_UID_DENIED=PASS')\n sys.exit(0)\ns.close()\nsys.exit(1)\n"
 out,err:=exec.Command("sudo","-n","-u","#65534","--","python3","-c",script,path).CombinedOutput()
 if err!=nil||!strings.Contains(string(out),"RAW_QMP_DISTINCT_UID_DENIED=PASS"){t.Fatalf("distinct UID denial not observed: %v %s",err,out)}
 q,err:=connectProtectedQMP(path,cmd.Process.Pid)
 if err!=nil{t.Fatal(err)}
 defer q.conn.Close()
 o,err:=claimAndNegotiateQMP(q)
 if err!=nil{t.Fatal(err)}
 defer o.Close()
 if pristine,e:=q.prelaunchOnly();e!=nil||!pristine{t.Fatalf("protected QMP prelaunch: %v %v",pristine,e)}
 t.Log("PROTECTED_QMP_REAL_TCG_DISTINCT_UID_DENIED=PASS")
}
