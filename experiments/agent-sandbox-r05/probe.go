// Public synthetic R05: exercise system-enforced container I/O denials and
// process-tree teardown. Not a malicious agent or a proven isolation boundary.
package main
import (
 "errors"
 "fmt"
 "net"
 "os"
 "os/exec"
 "strings"
 "syscall"
 "time"
)

const marker="/tmp/r05-marker"
func fail(err error) { if err!=nil { fmt.Fprintln(os.Stderr,err); os.Exit(1) } }
func examine() error {
 if _,err:=os.Stat(marker);err==nil {return errors.New("new sandbox unexpectedly contains prior marker")} else if !os.IsNotExist(err){return err}
 if err:=os.WriteFile("/etc/r05-forbidden-write",[]byte("blocked"),0600);err==nil {return errors.New("readonly root unexpectedly writable")}
 fmt.Println("R05_READONLY_ROOT_DENIED=PASS")
 hostMarker:=os.Getenv("R05_HOST_MARKER")
 if hostMarker=="" || !strings.HasPrefix(hostMarker,"/") {return errors.New("missing synthetic host marker path")}
 if _,err:=os.ReadFile(hostMarker);err==nil {return errors.New("synthetic host-only marker exposed")}else if !os.IsNotExist(err){return fmt.Errorf("marker: %w",err)}
 for _,p:=range []string{"/var/run/docker.sock","/host/recovery","/host/physical-tpm","/run/host-secrets"}{
  if _,err:=os.Stat(p);err==nil {return fmt.Errorf("unexpected host resource: %s",p)}else if !os.IsNotExist(err){return fmt.Errorf("host probe %s: %w",p,err)}
 }
 fmt.Println("R05_HOST_PATHS_AND_SYNTHETIC_MARKER_NOT_VISIBLE=PASS")
 c,err:=net.DialTimeout("tcp","192.0.2.1:80",600*time.Millisecond)
 if err==nil{c.Close();return errors.New("TEST-NET egress unexpectedly permitted")}
 var oe *net.OpError
 if !errors.As(err,&oe) { return fmt.Errorf("network failure is not network operation error: %w",err) }
 var se syscall.Errno
 if !errors.As(err,&se) || (se!=syscall.ENETUNREACH && se!=syscall.EHOSTUNREACH && se!=syscall.ENETDOWN){
  return fmt.Errorf("network not proven unreachable: %w",err)
 }
 fmt.Println("R05_ACTUAL_NETWORK_EGRESS_DENIED=PASS")
 return nil
}
func main() {
 if len(os.Args)!=2 {fail(errors.New("usage: /probe serve|child|grandchild|examine|mark|empty"));return}
 mode:=os.Args[1]
 switch mode {
 case "examine": fail(examine())
 case "mark": fail(os.WriteFile(marker,[]byte("synthetic"),0600));fmt.Println("R05_GUEST_LOCAL_STATE_WRITABLE=PASS")
 case "empty":
  _,err:=os.Stat(marker); if os.IsNotExist(err){fmt.Println("R05_RESTARTED_GUEST_STATE_EMPTY=PASS");return};fail(fmt.Errorf("marker still present/other error: %v",err))
 case "serve","child":
  next:="child"; if mode=="child"{next="grandchild"}
  ex,err:=os.Executable();fail(err)
  cmd:=exec.Command(ex,next)
  cmd.SysProcAttr=&syscall.SysProcAttr{Setsid:true}
  fail(cmd.Start())
  if mode=="serve"{fail(os.WriteFile("/tmp/r05-ready",[]byte("ready"),0600));fmt.Println("R05_PROCESS_TREE_STARTED=PASS")}
  for {time.Sleep(20*time.Second)}
 case "grandchild":
  for {time.Sleep(20*time.Second)}
 default: fail(fmt.Errorf("unknown mode: %s",mode))
 }
}
