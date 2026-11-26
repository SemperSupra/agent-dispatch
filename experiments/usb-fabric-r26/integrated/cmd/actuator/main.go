// R26-L2 synthetic sole-QMP actuator: the frontend has only this Unix socket.
// No REST listener, network authentication, privileged device access or
// distributed fencing is implemented here. Only a trusted per-host service
// should ever be allowed to start this process in a production design.
package main

import (
 "bufio"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "sync"
 "syscall"
 "time"

 blue "example.org/usb-fabric-r26-integrated/blue"
 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
 "example.org/usb-fabric-r26-releasegate/runtimeproof"
)
// ErrGuestUnconfirmed is a safety hold: QMP ACK does not prove that the
// actual guest released the key. A later independently authenticated guest
// receipt must authorize clearing the durable held-input journal.
var errGuestUnconfirmed=errors.New("guest release not independently confirmed")

// acquireOwner pins an OS advisory owner lock to the same host-controlled
// journal namespace that fences guest input. A Go mutex cannot guard two
// independent actuator PIDs or two separate QMP monitors of one VM.
//
// This synthetic capability does NOT authenticate the state directory,
// prevent a different journal namespace or arbitrary raw QMP actor, or
// survive an adversary unlinking the lockfile. A production host controller
// must enforce canonical VM identity and a private immutable state root.
func acquireOwner(journalPath string)(*os.File,error){
 if !filepath.IsAbs(journalPath){return nil,errors.New("owner journal path must be absolute")}
 lockPath:=journalPath+".owner.lock"
 fd,err:=syscall.Open(lockPath,syscall.O_CREAT|syscall.O_RDWR|
  syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0600)
 if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(fd),lockPath)
 if f==nil {syscall.Close(fd);return nil,errors.New("owner lock descriptor unavailable")}
 info,err:=f.Stat()
 if err!=nil || !info.Mode().IsRegular() || info.Mode().Perm()!=0600 {
  f.Close()
  return nil,errors.New("owner lock state is not regular mode-0600")
 }
 if err:=syscall.Flock(fd,syscall.LOCK_EX|syscall.LOCK_NB);err!=nil {
  f.Close()
  return nil,err
 }
 // Leave the lockfile in place when the process exits: unlinking permits
 // a replacement inode and two simultaneous lock holders.
 return f,nil
}

// acquireVMOwner closes the alternative-journal bypass in the synthetic
// same-host topology. Linux SO_PEERCRED identifies the QEMU socket server
// process; boot ID and /proc start ticks distinguish PID reuse. Every QMP
// socket served by the same QEMU PID maps to the SAME host-global lock even
// when its socket path and the caller's journal path differ.
//
// TEST SCOPE ONLY: a trusted controller must supply a protected host-wide
// state root, VM incarnation and authorization policy. /tmp and same-UID
// processes are NOT an adversary-resistant trust boundary.
type vmOwner struct{
 file *os.File
 alias net.Listener
}
func (o *vmOwner)Close()error {
 if o.alias!=nil{_ = o.alias.Close()}
 if o.file!=nil{return o.file.Close()}
 return nil
}
func acquireVMOwner(conn net.Conn)(*vmOwner,error) {
 unix,ok:=conn.(*net.UnixConn)
 if !ok{return nil,errors.New("QMP owner connection is not Unix")}
 raw,err:=unix.SyscallConn()
 if err!=nil{return nil,err}
 var cred *syscall.Ucred
 var sockErr error
 if err=raw.Control(func(fd uintptr){
  cred,sockErr=syscall.GetsockoptUcred(int(fd),syscall.SOL_SOCKET,syscall.SO_PEERCRED)
 });err!=nil{return nil,err}
 if sockErr!=nil{return nil,sockErr}
 if cred==nil || cred.Pid<=1 || cred.Uid!=uint32(os.Geteuid()){
  return nil,errors.New("QMP peer UID/PID untrusted")
 }
 rawStat,err:=os.ReadFile("/proc/"+strconv.Itoa(int(cred.Pid))+"/stat")
 if err!=nil{return nil,err}
 end:=strings.LastIndexByte(string(rawStat),')')
 if end<0{return nil,errors.New("QMP /proc starttime parse failed")}
 fields:=strings.Fields(string(rawStat[end+1:]))
 if len(fields)<20{return nil,errors.New("QMP /proc starttime missing")}
 ticks:=fields[19]
 if ticks==""{return nil,errors.New("empty process starttime")}
 rawBoot,err:=os.ReadFile("/proc/sys/kernel/random/boot_id")
 if err!=nil{return nil,err}
 bootID:=strings.TrimSpace(string(rawBoot))
 if len(bootID)<8{return nil,errors.New("invalid boot incarnation")}
 // The unprivileged same-UID adversary may replace lock pathnames.
 // A kernel-registered AF_UNIX abstract address remains busy while the
 // owning process is alive. The name is bound to peer PID/start/boot/UID.
 incarnation:=sha256.Sum256([]byte(fmt.Sprintf("%d/%d/%s/%s",
  cred.Uid,cred.Pid,bootID,ticks)))
 aliasName:=fmt.Sprintf("@r26-vm-%x",incarnation[:16])
 alias,err:=net.Listen("unix",aliasName)
 if err!=nil{
  if errors.Is(err,syscall.EADDRINUSE){
   fmt.Fprintln(os.Stderr,"R26_L10_ABSTRACT_VM_OWNER_ALREADY_BOUND=PASS")
   return nil,syscall.EWOULDBLOCK
  }
  return nil,err
 }
 defer func(){if alias!=nil{_ = alias.Close()}}()
 dir:=fmt.Sprintf("/tmp/.r26-sole-qmp-owner-%d",os.Geteuid())
 if err=os.Mkdir(dir,0700);err!=nil && !errors.Is(err,os.ErrExist){return nil,err}
 info,err:=os.Lstat(dir)
 if err!=nil{return nil,err}
 stat,ok:=info.Sys().(*syscall.Stat_t)
 if !ok || !info.IsDir() || info.Mode().Perm()!=0700 || stat.Uid!=uint32(os.Geteuid()){
  return nil,errors.New("host owner lock root is not private")
 }
 path:=filepath.Join(dir,fmt.Sprintf("vm-%d-%s-%s.lock",cred.Pid,bootID,ticks))
 fd,err:=syscall.Open(path,syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0600)
 if err!=nil{return nil,err}
 file:=os.NewFile(uintptr(fd),path)
 if file==nil{syscall.Close(fd);return nil,errors.New("VM lock descriptor unavailable")}
 details,err:=file.Stat()
 if err!=nil || !details.Mode().IsRegular() || details.Mode().Perm()!=0600 {
  file.Close();return nil,errors.New("VM lock state not regular mode-0600")
 }
 if err=syscall.Flock(fd,syscall.LOCK_EX|syscall.LOCK_NB);err!=nil{
  file.Close();return nil,err
 }
 owner:=&vmOwner{file:file,alias:alias}
 alias=nil
 return owner,nil
}

type qmp struct {
 mu sync.Mutex
 conn net.Conn
 enc *json.Encoder
 dec *json.Decoder
 deleted map[string]bool
}
// connectQMP establishes a transport only. No QMP command or greeting is
// consumed before the original host owner fence is acquired.
func connectQMP(path string)(*qmp,error){
 var conn net.Conn;var err error
 for i:=0;i<150;i++{
  conn,err=net.DialTimeout("unix",path,500*time.Millisecond)
  if err==nil{break}
  time.Sleep(40*time.Millisecond)
 }
 if err!=nil{return nil,err}
 return &qmp{conn:conn,enc:json.NewEncoder(conn),dec:json.NewDecoder(conn)},nil
}

// claimAndNegotiateQMP retains the original Linux VM owner fence during
// protocol negotiation and all subsequent actuator use. A denied second
// cooperative actuator must not negotiate a raw QMP capability first.
// This does not revoke an FD already leaked by a trusted controller.
func claimAndNegotiateQMP(q *qmp)(*vmOwner,error){
 owner,err:=acquireVMOwner(q.conn)
 if err!=nil{return nil,err}
 if err=q.negotiate();err!=nil{
  _=owner.Close()
  return nil,err
 }
 return owner,nil
}

func(q *qmp) negotiate()error{
 if err:=q.conn.SetDeadline(time.Now().Add(10*time.Second));err!=nil{return err}
 var greet map[string]json.RawMessage
 if err:=q.dec.Decode(&greet);err!=nil{return err}
 if _,ok:=greet["QMP"];!ok{return errors.New("QMP greeting absent")}
 return q.call("qmp_capabilities",nil)
}
func (q *qmp) call(name string,args map[string]any)error{
 q.mu.Lock();defer q.mu.Unlock()
 _=q.conn.SetDeadline(time.Now().Add(10*time.Second))
 msg:=map[string]any{"execute":name}
 if args!=nil{msg["arguments"]=args}
 if err:=q.enc.Encode(msg);err!=nil{return err}
 for i:=0;i<150;i++{
  var response map[string]json.RawMessage
  if err:=q.dec.Decode(&response);err!=nil{return err}
  if _,ok:=response["event"];ok{q.recordQMPEvent(response);continue}
  if e,ok:=response["error"];ok{return fmt.Errorf("QMP %s: %s",name,string(e))}
  if _,ok:=response["return"];ok{return nil}
  return errors.New("QMP response missing return")
 }
 return errors.New("QMP response limit")
}
// prelaunchOnly verifies the exact QMP VM run-state before admitting the
// FIRST synthetic lease. QEMU's "paused" state is insufficient: the guest
// might already have run and observed held input, then been stopped.
func (q *qmp) prelaunchOnly()(bool,error){
 q.mu.Lock();defer q.mu.Unlock()
 _=q.conn.SetDeadline(time.Now().Add(10*time.Second))
 if err:=q.enc.Encode(map[string]any{"execute":"query-status"});err!=nil{return false,err}
 for i:=0;i<150;i++{
  var response map[string]json.RawMessage
  if err:=q.dec.Decode(&response);err!=nil{return false,err}
  if _,ok:=response["event"];ok{continue}
  if raw,ok:=response["error"];ok{
   return false,fmt.Errorf("QMP query-status: %s",string(raw))
  }
  if raw,ok:=response["return"];ok{
   var status struct{
    Running bool `json:"running"`
    Status string `json:"status"`
   }
   if err:=json.Unmarshal(raw,&status);err!=nil{return false,err}
   if status.Status==""{return false,errors.New("missing VM run state")}
   return !status.Running && status.Status=="prelaunch",nil
  }
  return false,errors.New("QMP status response missing return")
 }
 return false,errors.New("QMP status response limit")
}

type executor struct {
 q *qmp
 journal heldledger.Store
 gate *releasegate.Gate // optional TEST-ONLY evdev proof gate, never a client API
 runtimeProof *runtimeproof.Authority // host-pinned Ed25519 path (synthetic)
 mu sync.Mutex
}
func (e *executor) qmpKey(down bool)error {
 return e.q.call("input-send-event",map[string]any{"events":[]any{
  map[string]any{"type":"key","data":map[string]any{
   "down":down,"key":map[string]any{"type":"qcode","data":"a"},
  }},
 }})
}
// Held=true is fsynced BEFORE a potentially effective QMP keydown.
// A QMP key-up ACK alone MUST NOT fsync held=false. Until a separate
// trustworthy guest receipt exists, preserve held=true and quarantine.
// Partial errors likewise preserve held=true for emergency restart recovery.
func (e *executor) Input(command string)error {
 e.mu.Lock();defer e.mu.Unlock()
 switch command {
 case "key-a-down":
  state,err:=e.journal.Read()
  if err!=nil{return err}
  if state.Held{return blue.ErrDenied}
  if _,err=e.journal.Transition(state.Sequence,true);err!=nil{return err}
  return e.qmpKey(true)
 case "key-a-up":
  state,err:=e.journal.Read()
  if err!=nil{return err}
  if state.Held && state.ReleasePhase=="" {
   // Durable intent is committed before potentially effective QMP key-up.
   if _,err=e.journal.RequestRelease(state.Sequence);err!=nil{return err}
  }
  if err:=e.qmpKey(false);err!=nil{return err}
  if state.Held {
   if state.ReleasePhase!="qmp-acked" {
    // A QMP ACK is a RELEASE STAGE only; it never clears Held.
    if _,err=e.journal.AcknowledgeQMPRelease(state.Sequence);err!=nil{return err}
   }
   if e.runtimeProof!=nil {
    // The solely authorized QMP actuator has just received real ACK and
    // fsynced its release stage. No guest message may set this flag.
    if err:=e.runtimeProof.MarkQMPAcknowledged();err!=nil{
     return errGuestUnconfirmed
    }
   }
   if e.gate!=nil {
    // Dynamic L9C lease scope, assigned only by the sole host actuator;
    // original L9B remains static unless --scoped-receipts is enabled.
    scope:=e.gate.Snapshot().Scope
    if err:=e.gate.RequestRelease(scope);err==nil{
     _=e.gate.AcknowledgeQMP(scope)
    }
   }
   return errGuestUnconfirmed
  }
  return nil
 default:return blue.ErrDenied
 }
}
func (e *executor) ReleaseAll()error{return e.Input("key-a-up")}

type request struct{
 Op string `json:"op"`
 Actor string `json:"actor"`
 Epoch string `json:"epoch"`
 Generation uint64 `json:"generation"`
 Command string `json:"command"`
}
type response struct{
 OK bool `json:"ok"`
 Error string `json:"error,omitempty"`
 State blue.State `json:"state,omitempty"`
 Epoch string `json:"epoch,omitempty"`
 Generation uint64 `json:"generation,omitempty"`
 Port *PortInfo `json:"port,omitempty"`
 Ports []PortInfo `json:"ports,omitempty"`
}
type actuator struct{
 m *blue.Manager
 q *qmp
 media,pcap string
 attachMu sync.Mutex
 devicesAttached,vmStarted bool
 proofMu sync.Mutex
 firstDownSequence uint64
 bridge *evidence.Bridge
 gate *releasegate.Gate
 journal heldledger.Store
 receiptConn net.Conn
 receiptWriteMu sync.Mutex
 scoped bool
 scope releasegate.Scope
 ex *executor
 runtimeMode bool
 pinnedGuestKey ed25519.PublicKey
 runtimeProof *runtimeproof.Authority
 authorizedPeerUID int
 policy operationPolicy
}

// Test-only first-hand guest evdev evidence ingress. The QEMU virtio-serial
// connection is host-local and never exposed to the unprivileged frontend.
// MAC material is PUBLIC in this research branch: DO NOT use for real auth.
func (a *actuator)startReceiptReader(path string)error {
 if path==""{return nil}
 if !a.scoped && (a.bridge==nil||a.gate==nil){return errors.New("missing guest proof verifier")}
 var conn net.Conn
 var err error
 for i:=0;i<50;i++{
  conn,err=net.DialTimeout("unix",path,500*time.Millisecond)
  if err==nil{break}
  time.Sleep(40*time.Millisecond)
 }
 if err!=nil{return err}
 a.receiptConn=conn
 go func(){
  decoder:=json.NewDecoder(bufio.NewReader(conn))
  for {
   if a.runtimeMode{
    var event runtimeproof.Event
    if err:=decoder.Decode(&event);err!=nil{
     fmt.Fprintln(os.Stderr,"R27C_GUEST_PROOF_CHANNEL_LOST=OBSERVED",err)
     a.m.Offline()
     return
    }
    a.applyRuntimeGuestReceipt(event)
   }else{
    var event evidence.Event
    if err:=decoder.Decode(&event);err!=nil{
     fmt.Fprintln(os.Stderr,"R26_L9B_GUEST_RECEIPT_CHANNEL_LOST=OBSERVED",err)
     a.m.Offline() // lack of a trusted sensor is never an availability signal
     return
    }
    a.applyGuestReceipt(event)
   }
  }
 }()
 return nil
}
func (a *actuator)applyGuestReceipt(event evidence.Event){
 if a.scoped{a.applyScopedGuestReceipt(event);return}
 if a.bridge==nil || event.Scope!=guestwire.Scope(){return}
 if event.Down {
  if err:=a.bridge.ObserveDown(event);err!=nil{return}
  a.proofMu.Lock()
  a.firstDownSequence=event.EventSequence
  a.proofMu.Unlock()
  fmt.Println("R26_L9B_FIRST_REAL_GUEST_EVDEV_DOWN_VERIFIED=PASS")
  return
 }
 a.proofMu.Lock()
 down:=a.firstDownSequence
 a.proofMu.Unlock()
 if down==0||!guestwire.VerifySyntheticGuest(event) || event.EventSequence<=down {
  return
 }
 // A guest can observe key-up before the host has received the QMP ACK.
 // Buffer the real signed receipt until the host has fsynced the QMP ACK.
 // If the ACK never arrives, quarantine; do not infer it from guest alone.
 var state heldledger.State
 var err error
 ready:=false
 for i:=0;i<150;i++{
  state,err=a.journal.Read()
  if err!=nil{return}
  if state.Held && state.ReleasePhase=="qmp-acked" &&
    a.gate.Snapshot().Phase==releasegate.QMPAcknowledged {
   ready=true
   break
  }
  time.Sleep(20*time.Millisecond)
 }
 if !ready{return}
 if err=a.bridge.ConfirmUp(event);err!=nil{return}
 claim:=heldledger.ReleaseClaim{
  GuestID:event.Scope.GuestID,DeviceID:event.Scope.DeviceID,
  HostEpoch:event.Scope.HostEpoch,GuestEpoch:event.Scope.GuestEpoch,
  LeaseEpoch:event.Scope.LeaseEpoch,Generation:event.Scope.Generation,
  ReleaseSequence:event.Scope.ReleaseSequence,DownEventSequence:down,
  EventSequence:event.EventSequence,Source:event.Source,
  Key:heldledger.KeyA,KeyReleased:!event.Down,Proof:event.Proof,
 }
 verifier:=func(c heldledger.ReleaseClaim)bool{
  return guestwire.VerifySyntheticGuest(event) &&
   c.GuestID==event.Scope.GuestID && c.DeviceID==event.Scope.DeviceID &&
   c.HostEpoch==event.Scope.HostEpoch && c.GuestEpoch==event.Scope.GuestEpoch &&
   c.LeaseEpoch==event.Scope.LeaseEpoch &&
   c.Generation==event.Scope.Generation &&
   c.ReleaseSequence==event.Scope.ReleaseSequence &&
   c.DownEventSequence==down && c.EventSequence==event.EventSequence &&
   c.Source==event.Source && c.Key==heldledger.KeyA &&
   c.KeyReleased && c.Proof==event.Proof
 }
 if err:=a.m.RestoreAfterVerifiedGuestUp(a.journal,state.Sequence,claim,verifier);err!=nil{
  fmt.Fprintln(os.Stderr,"R26_L9B_RECEIPT_REJECTED_LEDGER_REMAINS_HELD=OBSERVED",err)
  return
 }
 a.proofMu.Lock()
 a.firstDownSequence=0
 a.proofMu.Unlock()
 fmt.Println("R26_L9B_REAL_GUEST_VERIFIED_RELEASE_FSYNC_AND_READMISSION=PASS")
}
func (a *actuator) attach()error {
 a.attachMu.Lock();defer a.attachMu.Unlock()
 if a.devicesAttached{return nil}
 commands:=[]struct{name string;args map[string]any}{
  {"device_add",map[string]any{"driver":"usb-kbd","id":"r26-l-kbd","bus":"xhci0.0","pcap":a.pcap}},
  {"device_add",map[string]any{"driver":"usb-tablet","id":"r26-l-tablet","bus":"xhci0.0"}},
  {"blockdev-add",map[string]any{"driver":"file","filename":a.media,"node-name":"r26-l-file","read-only":true}},
  {"blockdev-add",map[string]any{"driver":"raw","file":"r26-l-file","node-name":"r26-l-raw","read-only":true}},
  {"device_add",map[string]any{"driver":"usb-storage","id":"r26-l-storage","drive":"r26-l-raw","bus":"xhci0.0"}},
 }
 for _,c:=range commands{
  if err:=a.q.call(c.name,c.args);err!=nil{
   a.m.Offline()
   return err
  }
 }
 a.devicesAttached=true
 return nil
}
func (a *actuator) start()error{
 a.attachMu.Lock();defer a.attachMu.Unlock()
 if a.vmStarted{return nil}
 if err:=a.q.call("cont",nil);err!=nil{
  a.m.Offline()
  return err
 }
 a.vmStarted=true
 return nil
}
func (a *actuator) handle(c net.Conn){
 defer c.Close()
 if err:=authorizePeer(c,a.authorizedPeerUID);err!=nil{
  fmt.Fprintln(os.Stderr,"R27_UNTRUSTED_SOCKET_PEER_DENIED=PASS")
  return
 }
 reader:=json.NewDecoder(bufio.NewReader(c))
 writer:=bufio.NewWriter(c)
 write:=func(r response){
  b,_:=json.Marshal(r)
  fmt.Fprintln(writer,string(b))
  _=writer.Flush()
 }
 var held blue.Lease
 defer func(){
  if held.Generation!=0{
   if err:=a.m.Revoke(held);err!=nil{
    if errors.Is(err,errGuestUnconfirmed) {
     fmt.Println("R26_L_ACK_ONLY_RELEASE_QUARANTINED_PENDING_GUEST_PROOF=PASS")
    }else{
     fmt.Fprintln(os.Stderr,"R26_L_RELEASE_FAILURE_QUARANTINE=RED",err)
    }
   }else{
    fmt.Println("R26_L_ACTUATOR_CLIENT_LOSS_RELEASE_ACCEPTED=PASS")
   }
  }
 }()
 for {
  _=c.SetReadDeadline(time.Now().Add(90*time.Second))
  var req request
  if err:=reader.Decode(&req);err!=nil{return}
  // Kernel-verified principal and host-configured grants are the only
  // authority in opt-in synthetic protected mode. Never accept client
  // JSON role, UID or capabilities.
  if !a.policy.may(req.Op){
   write(response{Error:ErrCapabilityDenied.Error()})
   continue
  }
  if req.Op=="status"||req.Op=="ports"{
   port,err:=a.status()
   if err!=nil{write(response{Error:err.Error()});continue}
   if req.Op=="status"{write(response{OK:true,State:port.State,Port:&port})
   }else{write(response{OK:true,Ports:[]PortInfo{port}})}
   continue
  }
  // The fixed actor is a synthetic test selector, NOT authentication.
  if req.Actor!="approved-agent" {
   write(response{Error:"actor denied"});continue
  }
  if req.Op=="reserve"{
   if held.Generation!=0{write(response{Error:"connection already has lease"});continue}
   l,err:=a.m.Reserve(req.Actor,"keyboard","xhci0/auto")
   if err!=nil{write(response{Error:err.Error()});continue}
   held=l
   write(response{OK:true,State:blue.Reserved,Epoch:l.Epoch,Generation:l.Generation})
   continue
  }
  wanted:=blue.Lease{Device:"keyboard",Port:"xhci0/auto",Actor:req.Actor,Epoch:req.Epoch,Generation:req.Generation}
  if held.Generation==0 || wanted!=held {
   write(response{Error:"missing or stale connection lease"});continue
  }
  var err error
  switch req.Op{
  case "attach":
   err=a.m.Attach(held)
   if err==nil{err=a.attach()}
  case "start":
   state,active,_:=a.m.Snapshot()
   if state!=blue.Attached || active!=held{err=blue.ErrDenied}else{
    err=a.start()
    if err==nil && a.scoped{err=a.bindGuestLease(held)}
   }
  case "input":
   if req.Command!="key-a-down" && req.Command!="key-a-up" {
    err=blue.ErrDenied
   }else{err=a.m.Input(held,req.Command)}
  case "revoke":
   err=a.m.Revoke(held)
   if err==nil{held=blue.Lease{}}
  case "detach":
   if !a.scoped{err=blue.ErrDenied}else{
    snapshot,_,_:=a.m.Snapshot()
    state,readErr:=a.journal.Read()
    if readErr!=nil{err=readErr
    }else if snapshot!=blue.Available || state.Held ||
      state.ReleasePhase!=""{err=blue.ErrDenied
    }else{
     err=a.m.BeginDetach()
     if err==nil{err=a.detachKeyboard()}
    }
   }
  default:
   err=blue.ErrDenied
  }
  if err!=nil{write(response{Error:err.Error()});continue}
  state,_,_:=a.m.Snapshot()
  write(response{OK:true,State:state})
 }
}
func main(){
 qmpPath:=flag.String("qmp","","QEMU local QMP Unix socket; never passed to clients")
 protectedQMPPID:=flag.Int("qmp-protected-pid",0,"trusted controller-pinned QEMU PID; require private socket directory and kernel peer match; zero is legacy lab mode")
 socketPath:=flag.String("socket","","new owned frontend Unix socket")
 media:=flag.String("media","","synthetic media path")
 pcap:=flag.String("capture","","synthetic USB capture path")
 journalPath:=flag.String("journal","","host-local fsynced key state path")
 // Optional source-identified R26-L8 synthetic QEMU virtio guest data plane.
 // It carries PUBLIC TEST-ONLY MAC events; not production authentication.
 receiptPath:=flag.String("receipt","","test-only QEMU virtio-serial receipt Unix socket")
 scopedReceipts:=flag.Bool("scoped-receipts",false,"test-only per-lease guest receipt scope with host-to-guest binding")
 runtimePubPath:=flag.String("runtime-guest-public","","host BUILDER-pin of QEMU guest Ed25519 image public key; synthetic only")
 authorizedPeerUID:=flag.Int("authorized-peer-uid",-1,"opt-in kernel SO_PEERCRED allowed host-local UID; -1 legacy test")
 operations:=flag.String("permitted-operations","","optional strict comma-separated host-granted operation allowlist")
 protectedFrontend:=flag.Bool("protected-frontend",false,"require dedicated controller and distinct peer UID, explicit grant, group-traversable private frontend directory")
 flag.Parse()
 if *qmpPath==""||*socketPath==""||*media==""||*pcap==""||*journalPath==""{
  fmt.Fprintln(os.Stderr,"missing QMP/socket/media/capture/journal");os.Exit(2)
 }
 policy,err:=parseOperationPolicy(*operations)
 if err!=nil || (policy.configured && *authorizedPeerUID<0){
  fmt.Fprintln(os.Stderr,"invalid operation grant or kernel peer authorization absent");os.Exit(16)
 }
 if *protectedFrontend{
  if err=validateProtectedFrontend(*protectedQMPPID,*authorizedPeerUID,policy,*scopedReceipts,*runtimePubPath,*receiptPath);err!=nil{
   fmt.Fprintln(os.Stderr,"protected frontend rejected:",err);os.Exit(16)
  }
 }
 owner,err:=acquireOwner(*journalPath)
 if err!=nil{
  if errors.Is(err,syscall.EWOULDBLOCK){
   fmt.Fprintln(os.Stderr,"R26_L6_QMP_OWNER_LOCK_BUSY=PASS")
  }else{
   fmt.Fprintln(os.Stderr,"R26_L6_OWNER_LOCK_STATE_UNTRUSTED=RED",err)
  }
  os.Exit(10)
 }
 defer owner.Close()
 var q *qmp
 if *protectedQMPPID!=0{
  q,err=connectProtectedQMP(*qmpPath,*protectedQMPPID)
 }else{
  q,err=connectQMP(*qmpPath)
 }
 if err!=nil{fmt.Fprintln(os.Stderr,"QMP unavailable:",err);os.Exit(3)}
 defer q.conn.Close()
 vmOwner,err:=claimAndNegotiateQMP(q)
 if err!=nil{
  if errors.Is(err,syscall.EWOULDBLOCK){
   fmt.Fprintln(os.Stderr,"R26_L7_QMP_OWNER_LOCK_BUSY=PASS")
  }else{
   fmt.Fprintln(os.Stderr,"R26_L7_QMP_PEER_IDENTITY_UNTRUSTED=RED",err)
  }
  os.Exit(12)
 }
 defer vmOwner.Close()
 journal:=heldledger.Store{Path:*journalPath}
 recovered,err:=journal.Read()
 if err!=nil{
  fmt.Fprintln(os.Stderr,"R26_L3_CORRUPT_JOURNAL_QUARANTINE=RED",err)
  os.Exit(8)
 }
 ex:=&executor{q:q,journal:journal}
 if recovered.Held {
  // QMP ACK cannot prove that the guest input driver actually observed
  // key-up. Preserve the held journal and refuse client admission until
  // a separately authenticated guest/port reconciliation can clear it.
  // A subsequent restart repeats this idempotent emergency key-up.
  if err:=ex.qmpKey(false);err!=nil{
   fmt.Fprintln(os.Stderr,"R26_L3_RECOVERY_RELEASE_FAILED_QUARANTINE=RED",err)
   os.Exit(9)
  }
  fmt.Println("R26_L3_ACTUATOR_RESTART_FORCED_QMP_KEY_UP=PASS")
  fmt.Println("R26_L3_JOURNAL_REMAINS_HELD_PENDING_GUEST_ATTESTATION=PASS")
  fmt.Println("R26_L3_RECOVERY_HOLD_REQUIRES_TOPOLOGY_RECONCILIATION=PASS")
  return
 }
 // R26-L5: even a missing or apparently clean journal cannot establish
 // that an existing guest is safe for new input. Only a QEMU incarnation
 // that has NEVER started execution may bootstrap in this synthetic model.
 // Recovered, already-running, paused-after-run, unknown or QMP-offline
 // guests MUST remain unavailable until independently reconciled.
 //
 // This is NOT complete production first-boot proof: a real controller must
 // additionally attest USB topology, exclusive socket ownership, VM
 // incarnation, and persistent guest/host epoch before provisioning.
 pristine,err:=q.prelaunchOnly()
 if err!=nil || !pristine {
  fmt.Fprintln(os.Stderr,"R26_L5_STALE_OR_UNKNOWN_GUEST_STARTUP_QUARANTINED=PASS",err)
  os.Exit(8)
 }
 fmt.Fprintln(os.Stderr,"R26_L5_NEVER_RAN_PRELAUNCH_CONTROL_PROOF=PASS")
 a:=&actuator{m:blue.New("keyboard","xhci0/auto",ex),q:q,
  media:*media,pcap:*pcap,journal:journal,scoped:*scopedReceipts,ex:ex,
  runtimeMode:*runtimePubPath!="",
  authorizedPeerUID:*authorizedPeerUID,policy:policy}
 if *scopedReceipts && *receiptPath=="" {
  fmt.Fprintln(os.Stderr,"per-lease receipt needs explicit synthetic guest channel");os.Exit(14)
 }
 if a.runtimeMode{
  if !a.scoped||*receiptPath==""{
   fmt.Fprintln(os.Stderr,"runtime Ed25519 requires scoped guest receipt channel");os.Exit(14)
  }
  // The pinned key comes from the CONTROLLED image build, never the guest
  // virtio transport. A public image private key remains extractable;
  // actual TPM/secure boot attestation is outside this synthetic gate.
  pub,err:=os.ReadFile(*runtimePubPath)
  if err!=nil||len(pub)!=ed25519.PublicKeySize{
   fmt.Fprintln(os.Stderr,"trusted image-builder guest key pin absent");os.Exit(14)
  }
  a.pinnedGuestKey=append(ed25519.PublicKey(nil),pub...)
  fmt.Println("R27C_HOST_BUILDER_GUEST_PUBLIC_KEY_PINNED=PASS")
 }
 if *receiptPath!="" {
  if !*scopedReceipts {
   scope:=guestwire.Scope()
   gate,err:=releasegate.New(scope)
   if err!=nil{fmt.Fprintln(os.Stderr,"invalid guest scope",err);os.Exit(14)}
   bridge,err:=evidence.New(gate,scope,guestwire.VerifySyntheticGuest)
   if err!=nil{fmt.Fprintln(os.Stderr,"guest proof bridge unavailable",err);os.Exit(14)}
   ex.gate=gate
   a.gate=gate
   a.bridge=bridge
  }
  if err=a.startReceiptReader(*receiptPath);err!=nil{
   fmt.Fprintln(os.Stderr,"guest receipt ingress unavailable",err);os.Exit(14)
  }
  defer a.receiptConn.Close()
 }
 // Publish the frontend only after policy, QMP, recovery and configured
 // guest receipt setup are complete. Protected mode is fail-closed.
 listener,err:=listenActuatorFrontend(*socketPath,*protectedFrontend)
 if err!=nil{fmt.Fprintln(os.Stderr,"frontend unavailable:",err);os.Exit(5)}
 defer listener.Close()
 fmt.Println("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
 for {
  c,err:=listener.Accept()
  if err!=nil{fmt.Fprintln(os.Stderr,"accept:",err);os.Exit(7)}
  go a.handle(c)
 }
}
