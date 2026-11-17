package main

// R26-K synthetic supervisor. This independent process survives the Go broker
// process and forces a release after broker exit. It is not a production
// multi-host fence or a security boundary against same-UID hostile processes.
import (
 "bufio"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "strconv"
 "strings"
 "syscall"
 "time"
)

func dead(pid int) bool {
 if err:=syscall.Kill(pid,0);errors.Is(err,syscall.ESRCH){return true}
 // A zombie has exited, but has not yet been reaped by its parent.
 content,err:=os.ReadFile("/proc/"+strconv.Itoa(pid)+"/stat")
 if errors.Is(err,os.ErrNotExist){return true}
 if err!=nil{return false}
 pos:=strings.LastIndexByte(string(content),')')
 if pos<0 || len(content)<=pos+2{return false}
 return content[pos+2]=='Z'
}

type session struct {
 conn net.Conn
 scanner *bufio.Scanner
}
func (s *session) read() (map[string]json.RawMessage,error) {
 if !s.scanner.Scan(){return nil,errors.New("QMP EOF")}
 var msg map[string]json.RawMessage
 err:=json.Unmarshal(s.scanner.Bytes(),&msg)
 return msg,err
}
func (s *session) command(name string,args map[string]any)error {
 request:=map[string]any{"execute":name}
 if args!=nil {request["arguments"]=args}
 payload,e:=json.Marshal(request)
 if e!=nil{return e}
 if _,e=s.conn.Write(append(payload,'\n'));e!=nil{return e}
 for i:=0;i<100;i++{
  msg,e:=s.read();if e!=nil{return e}
  if _,ok:=msg["event"];ok{continue}
  if errObj,ok:=msg["error"];ok{return fmt.Errorf("QMP %s: %s",name,string(errObj))}
  if _,ok:=msg["return"];ok{return nil}
 }
 return errors.New("QMP response limit")
}
func release(path string)error {
 deadline:=time.Now().Add(8*time.Second)
 var conn net.Conn
 var err error
 for time.Now().Before(deadline){
  conn,err=net.DialTimeout("unix",path,400*time.Millisecond)
  if err==nil{break}
  time.Sleep(50*time.Millisecond)
 }
 if err!=nil{return err}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(10*time.Second))
 s:=&session{conn:conn,scanner:bufio.NewScanner(conn)}
 msg,e:=s.read()
 if e!=nil{return e}
 if _,ok:=msg["QMP"];!ok{return errors.New("QMP greeting missing")}
 if e=s.command("qmp_capabilities",nil);e!=nil{return e}
 return s.command("input-send-event",map[string]any{"events":[]any{
  map[string]any{"type":"key","data":map[string]any{
   "down":false,"key":map[string]any{"type":"qcode","data":"a"},
  }},
 }})
}
func main(){
 pid:=flag.Int("broker-pid",0,"synthetic broker PID")
 path:=flag.String("qmp","","local QMP unix path")
 flag.Parse()
 if *pid<=1 || *path==""{fmt.Fprintln(os.Stderr,"invalid broker PID or QMP");os.Exit(2)}
 deadline:=time.Now().Add(45*time.Second)
 for !dead(*pid){
  if time.Now().After(deadline){fmt.Fprintln(os.Stderr,"R26_K_WATCHDOG_BROKER_NOT_DEAD=RED");os.Exit(3)}
  time.Sleep(25*time.Millisecond)
 }
 if err:=release(*path);err!=nil{
  fmt.Fprintln(os.Stderr,"R26_K_SUPERVISOR_RELEASE_FAILED_QUARANTINE=RED",err)
  os.Exit(4)
 }
 fmt.Println("R26_K_INDEPENDENT_PROCESS_FORCED_QMP_KEY_UP=PASS")
 fmt.Println("R26_K_PHYSICAL_MULTIHOST_PROCESS_FENCING=NOT_TESTED")
}
