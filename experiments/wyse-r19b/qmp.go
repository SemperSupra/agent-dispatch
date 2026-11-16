package qmpatomic

// R19B: real Linux-local QMP guarded by the same host mutex as fenced input
// and input release. Public synthetic QEMU TCG; no guest or physical USB.
import (
 "bufio"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "sync"
 "time"

 fence "example.org/wyse-r19-fence"
)

type machine struct {
 dir string
 process *exec.Cmd
 conn net.Conn
 reader *bufio.Reader
 mu sync.Mutex
}
func (m *machine) call(name string, args any)error{
 m.mu.Lock(); defer m.mu.Unlock()
 cmd:=map[string]any{"execute":name}
 if args!=nil{cmd["arguments"]=args}
 b,e:=json.Marshal(cmd);if e!=nil{return e}
 _=m.conn.SetDeadline(time.Now().Add(5*time.Second))
 if _,e=m.conn.Write(append(b,'\n'));e!=nil{return e}
 for k:=0;k<120;k++{
  line,e:=m.reader.ReadBytes('\n');if e!=nil{return e}
  var response map[string]json.RawMessage
  if e=json.Unmarshal(line,&response);e!=nil{return e}
  if _,yes:=response["event"];yes{continue}
  if errBytes,yes:=response["error"];yes{
   return fmt.Errorf("QMP %s denied: %s",name,errBytes)
  }
  if _,yes:=response["return"];yes{return nil}
  return errors.New("QMP returned no result")
 }
 return errors.New("QMP event flood")
}
func startMachine()(m *machine,err error){
 dir,e:=os.MkdirTemp("/tmp","r19b-")
 if e!=nil{return nil,e}
 m=&machine{dir:dir}
 sock:=filepath.Join(dir,"qmp.sock")
 args:=[]string{"-machine","q35","-cpu","qemu64","-accel","tcg",
  "-m","128M","-smp","1","-S","-nodefaults","-display","none",
  "-monitor","none","-serial","none","-net","none",
  "-device","qemu-xhci,id=xhci0",
  "-qmp","unix:"+sock+",server=on,wait=off"}
 m.process=exec.Command("qemu-system-x86_64",args...)
 if e=m.process.Start();e!=nil{m.Close();return nil,e}
 for i:=0;i<100;i++{
  conn,ee:=net.DialTimeout("unix",sock,time.Second)
  if ee==nil{
   m.conn=conn;m.reader=bufio.NewReader(conn)
   _=conn.SetReadDeadline(time.Now().Add(3*time.Second))
   welcome,ee:=m.reader.ReadBytes('\n')
   if ee!=nil{m.Close();return nil,ee}
   var hi map[string]json.RawMessage
   if json.Unmarshal(welcome,&hi)!=nil||hi["QMP"]==nil{
    m.Close();return nil,errors.New("missing QMP greeting")
   }
   if e=m.call("qmp_capabilities",nil);e!=nil{m.Close();return nil,e}
   if e=m.call("device_add",map[string]any{"driver":"usb-kbd","id":"kbd","bus":"xhci0.0"});e!=nil{m.Close();return nil,e}
   if e=m.call("device_add",map[string]any{"driver":"usb-tablet","id":"ptr","bus":"xhci0.0"});e!=nil{m.Close();return nil,e}
   if e=m.call("cont",nil);e!=nil{m.Close();return nil,e}
   return m,nil
  }
  time.Sleep(50*time.Millisecond)
 }
 m.Close();return nil,errors.New("QMP startup timeout")
}
func (m *machine)Close(){
 if m==nil{return}
 if m.conn!=nil{_ =m.conn.Close()}
 if m.process!=nil && m.process.Process!=nil{
  _=m.process.Process.Kill()
  _=m.process.Wait()
 }
 if m.dir!=""{_ =os.RemoveAll(m.dir)}
}
func event(kind string,down bool)map[string]any{
 var data map[string]any
 if kind=="hid.key_a"{
  data=map[string]any{"down":down,"key":map[string]any{"type":"qcode","data":"a"}}
  return map[string]any{"events":[]any{map[string]any{"type":"key","data":data}}}
 }
 data=map[string]any{"down":down,"button":"left"}
 return map[string]any{"events":[]any{map[string]any{"type":"btn","data":data}}}
}
type Host struct{
 mu sync.Mutex
 g *fence.Gate
 m *machine
 downKey bool
 downButton bool
 events []string
 unsafe bool
}
func newHost()(h *Host,err error){
 m,e:=startMachine()
 if e!=nil{return nil,e}
 g,e:=fence.NewGate(fence.NewStore())
 if e!=nil{m.Close();return nil,e}
 return &Host{g:g,m:m},nil
}
func (h *Host)Close(){if h!=nil{h.m.Close()}}
func (h *Host)Claim()(fence.Lease,error){
 h.mu.Lock();defer h.mu.Unlock()
 return h.g.Claim("actor-r19b","linux-guest","synthetic",time.Now().Add(12*time.Second))
}
func (h *Host)Input(r fence.Request,down bool)error{
 h.mu.Lock();defer h.mu.Unlock()
 if h.unsafe{return fence.ErrUnavailable}
 return h.g.Do(r,func()error{
  if e:=h.m.call("input-send-event",event(r.Capability,down));e!=nil{
   h.unsafe=true
   return e
  }
  if r.Capability=="hid.key_a"{h.downKey=down}else{h.downButton=down}
  h.events=append(h.events,fmt.Sprintf("QMP_%s_%v",r.Capability,down))
  return nil
 })
}
func (h *Host)Revoke()error{
 h.mu.Lock();defer h.mu.Unlock()
 if h.unsafe{return fence.ErrUnavailable}
 // Send release through ACTUAL QMP while holding host owner lock.
 for _,v:=range []struct{kind string;down *bool}{
  {"hid.key_a",&h.downKey},{"hid.button_left",&h.downButton}} {
  if *v.down{
   if e:=h.m.call("input-send-event",event(v.kind,false));e!=nil{
    h.unsafe=true
    return e
   }
   *v.down=false
   h.events=append(h.events,"QMP_RELEASE_"+v.kind)
  }
 }
 if e:=h.g.Revoke();e!=nil{h.unsafe=true;return e}
 h.events=append(h.events,"REVOKE_RETURNED")
 return nil
}
func (h *Host)Snapshot()[]string{
 h.mu.Lock();defer h.mu.Unlock()
 return append([]string(nil),h.events...)
}
