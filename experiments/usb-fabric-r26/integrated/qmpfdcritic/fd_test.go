package qmpfdcritic

import(
 "bufio"
 "fmt"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

// This RED witness tests the Linux FD lifetime and inheritance primitive,
// NOT a full QEMU exploit. An existing connected raw QMP FD survives unlink,
// and an actor with that FD can bypass pathname-only admission restrictions.
func TestChildWithInheritedQMPFD(t *testing.T){
 if os.Getenv("R27H24_INHERITED_QMP_CHILD")!="1"{t.Skip("helper subprocess only")}
 fd:=os.NewFile(uintptr(3),"inherited-raw-qmp")
 if fd==nil{t.Fatal("no inherited fd")}
 defer fd.Close()
 if _,err:=fmt.Fprint(fd,"{\"execute\":\"query-status\"}\n");err!=nil{t.Fatal(err)}
}

func TestREDExistingConnectedFDBypassesSocketPathRemoval(t *testing.T){
 dir:=t.TempDir()
 path:=filepath.Join(dir,"qmp.sock")
 listener,err:=net.Listen("unix",path)
 if err!=nil{t.Fatal(err)}
 defer listener.Close()
 client,err:=net.Dial("unix",path)
 if err!=nil{t.Fatal(err)}
 defer client.Close()
 server,err:=listener.Accept()
 if err!=nil{t.Fatal(err)}
 defer server.Close()
 unixClient:=client.(*net.UnixConn)
 inherited,err:=unixClient.File()
 if err!=nil{t.Fatal(err)}
 defer inherited.Close()
 // Unlinking prevents new pathname connects but cannot revoke an already
 // connected or inherited FD.
 if err=os.Remove(path);err!=nil{t.Fatal(err)}
 if fresh,e:=net.DialTimeout("unix",path,100*time.Millisecond);e==nil{
  fresh.Close()
  t.Fatal("unexpected fresh connection to unlinked QMP path")
 }
 cmd:=exec.Command(os.Args[0],"-test.run=^TestChildWithInheritedQMPFD$")
 cmd.Env=append(os.Environ(),"R27H24_INHERITED_QMP_CHILD=1")
 cmd.ExtraFiles=[]*os.File{inherited}
 if err=cmd.Start();err!=nil{t.Fatal(err)}
 _=server.SetReadDeadline(time.Now().Add(4*time.Second))
 line,err:=bufio.NewReader(server).ReadString('\n')
 if err!=nil{t.Fatal(err)}
 if err=cmd.Wait();err!=nil{t.Fatal(err)}
 if !strings.Contains(line,"\"execute\":\"query-status\""){t.Fatal("no hostile raw-QMP frame delivered",line)}
 t.Log("R27H24_INHERITED_FD_AFTER_UNLINK=RED: command frame reached established connection")
 t.Log("R27H24_FRESH_PATHNAME_CONNECTION_DENIED=PASS")
}
