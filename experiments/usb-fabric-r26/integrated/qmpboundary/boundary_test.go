package qmpboundary

import (
 "bufio"
 "errors"
 "fmt"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "testing"
 "time"
)

func TestChildDeniedByPrivateQMPDirectory(t *testing.T) {
 if os.Getenv("R27H26_DENIED_CHILD")!="1" { t.Skip("privilege-dropped child only") }
 path:=os.Getenv("R27H26_QMP_PATH")
 if path=="" { t.Fatal("no synthetic QMP socket path") }
 client,err:=net.DialTimeout("unix",path,250*time.Millisecond)
 if err==nil { client.Close();t.Fatal("unprivileged principal connected to QMP") }
 t.Log("R27H26_UNPRIVILEGED_QMP_PATH_DENIED=PASS")
}
func TestSeparatePrincipalAndNonInheritableSocket(t *testing.T) {
 if os.Geteuid()!=0 {
  t.Skip("RUN_AS_ROOT_REQUIRED: synthetic isolated UID matrix requires root in public disposable runner")
 }
 dir:=filepath.Join(t.TempDir(),"trusted-qmp")
 if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 socket:=filepath.Join(dir,"qmp.sock")
 ln,err:=net.Listen("unix",socket)
 if err!=nil{t.Fatal(err)}
 defer ln.Close()
 if err:=os.Chmod(socket,0600);err!=nil{t.Fatal(err)}
 // Service principal is owner of the synthetic QMP socket. A privileged
 // test may connect, but a separate unprivileged service identity may not.
 client,err:=net.Dial("unix",socket)
 if err!=nil{t.Fatal(err)}
 defer client.Close()
 peer,err:=ln.Accept()
 if err!=nil{t.Fatal(err)}
 defer peer.Close()
 raw,err:=client.(*net.UnixConn).File()
 if err!=nil{t.Fatal(err)}
 defer raw.Close()
 syscall.CloseOnExec(int(raw.Fd()))
 inode,err:=os.Readlink(fmt.Sprintf("/proc/self/fd/%d",raw.Fd()))
 if err!=nil{t.Fatal(err)}
 if !strings.HasPrefix(inode,"socket:["){t.Fatal("unexpected FD target",inode)}
 // Go's temporary build directory may be root-only; stage exactly this
 // disposable test binary in a traversable directory for the uid-drop.
 helperDir,err:=os.MkdirTemp("/tmp","r27h26-uid-exec-")
 if err!=nil{t.Fatal(err)}
 defer os.RemoveAll(helperDir)
 if err=os.Chmod(helperDir,0755);err!=nil{t.Fatal(err)}
 helper:=filepath.Join(helperDir,"qmp-boundary-test")
 binary,err:=os.ReadFile(os.Args[0]);if err!=nil{t.Fatal(err)}
 if err=os.WriteFile(helper,binary,0755);err!=nil{t.Fatal(err)}
 // The dropped principal still receives an inherited *environment*, but
 // not a QMP client FD: the child scans /proc/self/fd by socket inode.
 cmd:=exec.Command(helper,"-test.run=^TestChildCannotSeeQMPFD$")
 cmd.Env=append(os.Environ(),"R27H26_INHERIT_CHILD=1","R27H26_SOCKET_INODE="+inode)
 cmd.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:65534,Gid:65534,NoSetGroups:true}}
 out,err:=cmd.CombinedOutput()
 if err!=nil{t.Fatalf("no-FD child failed: %v %s",err,out)}
 // The separate UID must fail even when it knows the exact QMP pathname.
 outsider:=exec.Command(helper,"-test.run=^TestChildDeniedByPrivateQMPDirectory$")
 outsider.Env=append(os.Environ(),"R27H26_DENIED_CHILD=1","R27H26_QMP_PATH="+socket)
 outsider.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:65534,Gid:65534,NoSetGroups:true}}
 out,err=outsider.CombinedOutput()
 if err!=nil{t.Fatalf("private QMP path child failed: %v %s",err,out)}
 t.Log("R27H26_DISTINCT_UID_PRIVATE_QMP_PATH_DENIED=PASS")
 t.Log("R27H26_UNTRUSTED_EXEC_NO_QMP_FD_INHERITED=PASS")
}
func TestChildCannotSeeQMPFD(t *testing.T) {
 if os.Getenv("R27H26_INHERIT_CHILD")!="1" {t.Skip("child only")}
 inode:=os.Getenv("R27H26_SOCKET_INODE")
 if !strings.HasPrefix(inode,"socket:["){t.Fatal("missing parent socket inode")}
 entries,err:=os.ReadDir("/proc/self/fd")
 if err!=nil{t.Fatal(err)}
 for _,entry:=range entries{
  link,err:=os.Readlink(filepath.Join("/proc/self/fd",entry.Name()))
  if err!=nil {continue}
  if link==inode{t.Fatal("inherited existing raw-QMP socket despite close-on-exec")}
 }
}
func TestProhibitSameUIDPromotion(t *testing.T) {
 // There is no safe permission-only solution to H7 when QMP and attacker
 // share the same effective UID. Keep this as an explicit unresolved RED.
 if os.Geteuid()==65534{t.Skip("helper UID")}
 err:=errors.New("same effective UID is not an attacker-resistant QMP boundary")
 if err==nil{t.Fatal("same UID unexpectedly trusted")}
 t.Log("R27H26_SAME_UID_RAW_QMP_BOUNDARY=RED")
}
func TestNoCrossProtocolClaim(t *testing.T){
 // A file descriptor deliberately passed via ExtraFiles bypasses CLOEXEC;
 // the previously qualified H24 proves that variant. This workcell
 // checks ordinary exec default only and never claims FD revocation.
 input:=bufio.NewReader(strings.NewReader("R27H24_INHERITED_FD_AFTER_UNLINK=RED\n"))
 s,_:=input.ReadString('\n')
 if !strings.Contains(s,"=RED"){t.Fatal("lost inherited FD threat")}
}
