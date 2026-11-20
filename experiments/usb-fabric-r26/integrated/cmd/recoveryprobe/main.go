// R27-H20 disposable synthetic recovery-proof observer.
// It is deliberately NOT an authorized production controller: it uses a
// second test-only QMP monitor and does not clear HELD or admit a new lease.
// H7 proved same-service-UID access to an exposed raw QMP monitor is RED.
package main

import(
 "bufio"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "time"

 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
 "example.org/usb-fabric-r26-integrated/recoveryguard"
 "example.org/usb-fabric-r26-integrated/recoveryfence"
 "example.org/usb-fabric-r26-integrated/topology"
 "example.org/usb-fabric-r26-releasegate/guestwire"
 "example.org/usb-fabric-r26-releasegate/recoveryproof"
)
type binding struct{
 Op string `json:"Op"`
 Scope any `json:"Scope"`
 Challenge [32]byte `json:"Challenge"`
}
func qmpCall(conn net.Conn,enc *json.Encoder,dec *json.Decoder,name string,args map[string]any)(json.RawMessage,error){
 msg:=map[string]any{"execute":name}
 if args!=nil{msg["arguments"]=args}
 if err:=enc.Encode(msg);err!=nil{return nil,err}
 for i:=0;i<128;i++{
  var response map[string]json.RawMessage
  if err:=dec.Decode(&response);err!=nil{return nil,err}
  if _,ok:=response["event"];ok{continue}
  if v,ok:=response["error"];ok{return nil,fmt.Errorf("QMP %s: %s",name,v)}
  if v,ok:=response["return"];ok{return v,nil}
  return nil,errors.New("malformed QMP response")
 }
 return nil,errors.New("QMP response limit")
}
func run()error{
 qmpPath:=flag.String("qmp","","test-only host QMP socket")
 receiptPath:=flag.String("receipt","","virtio-serial host receipt socket")
 journalPath:=flag.String("journal","","durable HELD journal to audit without mutation")
 publicPath:=flag.String("public","","builder-pinned synthetic guest Ed25519 public key")
 epoch:=flag.String("epoch","","original host epoch")
 generation:=flag.Uint64("generation",0,"original lease generation")
 release:=flag.Uint64("release",0,"original held release sequence")
 priorDown:=flag.Uint64("down-event",10,"original signed evdev down sequence")
 flag.Parse()
 if *qmpPath==""||*receiptPath==""||*journalPath==""||*publicPath==""||*epoch==""||*generation==0||*release==0{return errors.New("missing exact source-scoped recovery inputs")}
 store:=heldledger.Store{Path:*journalPath}
 before,err:=store.Read();if err!=nil{return err}
 if !before.Held||before.Sequence!=*release{return errors.New("no exact durable held state")}
 pub,err:=os.ReadFile(*publicPath);if err!=nil||len(pub)!=ed25519.PublicKeySize{return errors.New("pinned public key unavailable")}
 scope:=guestwire.Scope()
 scope.HostEpoch=*epoch
 scope.LeaseEpoch=fmt.Sprintf("%s/%d",*epoch,*generation)
 scope.Generation=*generation
 scope.ReleaseSequence=*release
 challenge,err:=recoveryproof.Challenge();if err!=nil{return err}
 auth,err:=recoveryproof.NewAuthority(ed25519.PublicKey(pub),scope,challenge,*priorDown)
 if err!=nil{return err}
 // The same QEMU process and guest virtio port survive actuator SIGKILL.
 // Neither file/socket name alone authenticates the original VM incarnation.
 receipt,err:=net.DialTimeout("unix",*receiptPath,8*time.Second);if err!=nil{return err}
 defer receipt.Close()
 _=receipt.SetDeadline(time.Now().Add(35*time.Second))
 // Acquire both QMP and guest-receipt kernel peers BEFORE sending a
 // recovery command. Match PID/UID/starttime/boot and hold the bounded
 // abstract single-owner lock through signed guest UP verification.
 qmp,err:=net.DialTimeout("unix",*qmpPath,8*time.Second)
 if err!=nil{return err}
 defer qmp.Close()
 owner,err:=recoveryfence.Acquire(qmp,receipt)
 if err!=nil{return fmt.Errorf("R27H21_RECOVERY_PEER_OWNERSHIP_DENIED: %w",err)}
 defer owner.Close()
 fmt.Println("R27H21_QMP_RECEIPT_KERNEL_PEERS_MATCH=PASS")
 fmt.Println("R27H21_COOPERATIVE_RECOVERY_OWNER_LOCK_HELD=PASS")
 _=qmp.SetDeadline(time.Now().Add(35*time.Second))

 reader:=json.NewDecoder(bufio.NewReader(receipt))
 writer:=json.NewEncoder(receipt)
 if err=writer.Encode(binding{Op:"recover",Scope:scope,Challenge:challenge});err!=nil{return err}
 fmt.Println("R27H20_FRESH_HOST_RECOVERY_BIND_SENT=PASS")
 var snapshot recoveryproof.Event
 if err=reader.Decode(&snapshot);err!=nil{return fmt.Errorf("guest held snapshot absent: %w",err)}
 if err=auth.ObserveHeldSnapshot(snapshot);err!=nil{return fmt.Errorf("guest held snapshot untrusted: %w",err)}
 fmt.Println("R27H20_FRESH_SIGNED_GUEST_KERNEL_HELD_SNAPSHOT=PASS")
 qe:=json.NewEncoder(qmp);qd:=json.NewDecoder(bufio.NewReader(qmp))
 var greeting map[string]json.RawMessage
 if err=qd.Decode(&greeting);err!=nil{return err}
 if _,ok:=greeting["QMP"];!ok{return errors.New("QMP greeting absent")}
 if _,err=qmpCall(qmp,qe,qd,"qmp_capabilities",nil);err!=nil{return err}
 status,err:=qmpCall(qmp,qe,qd,"query-status",nil);if err!=nil{return err}
 var runState struct{Running bool `json:"running"`;Status string `json:"status"`}
 if err=json.Unmarshal(status,&runState);err!=nil||!runState.Running||runState.Status!="running"{return errors.New("surviving VM not actually running")}
 fmt.Println("R27H20_LIVE_QEMU_STATUS_BEFORE_EMERGENCY_UP=PASS")
 _,err=qmpCall(qmp,qe,qd,"input-send-event",map[string]any{"events":[]any{
  map[string]any{"type":"key","data":map[string]any{"down":false,"key":map[string]any{"type":"qcode","data":"a"}}},
 }})
 if err!=nil{return err}
 if err=auth.MarkEmergencyQMPAcknowledged();err!=nil{return err}
 fmt.Println("R27H20_EMERGENCY_QMP_ACK_NOT_GUEST_PROOF=PASS")
 var up recoveryproof.Event
 if err=reader.Decode(&up);err!=nil{return fmt.Errorf("postcrash evdev UP absent: %w",err)}
 if err=auth.ConfirmGuestKeyUp(up);err!=nil{return fmt.Errorf("postcrash signed UP untrusted: %w",err)}
 if !auth.Reclaimable(){return errors.New("fresh guest UP did not satisfy signed recovery verifier")}
 fmt.Println("R27H20_REAL_GUEST_EVDEV_POSTCRASH_SIGNED_UP=PASS")
 // Detach only AFTER independently signed guest-UP under the same fresh
 // recovery challenge. A QMP topology observation alone cannot clear HELD.
 query:=func(name string,args map[string]any)(json.RawMessage,error){
  return qmpCall(qmp,qe,qd,name,args)
 }
 removed,err:=topology.DetachAndConfirm(query,"r26-l-kbd")
 if err!=nil||!removed{return fmt.Errorf("R27H22_USB_TOPOLOGY_UNTRUSTED: %w",err)}
 fmt.Println("R27H22_REAL_QOM_DEVICE_REMOVAL_AFTER_GUEST_UP=PASS")

 after,err:=store.Read();if err!=nil{return err}
 if err=recoveryguard.VerifyEmergencyHold(before,after);err!=nil{return err}
 fmt.Println("R27H20_GUEST_UP_SIGNED_BUT_DURABLE_HELD_RETAINED=PASS")
 fmt.Println("R27H20_TOPOLOGY_OWNER_RECONCILIATION=NOT_TESTED")
 fmt.Println("R27H20_SAFE_LEASE_READMISSION=NOT_TESTED")
 return nil
}
func main(){
 if err:=run();err!=nil{
  fmt.Fprintln(os.Stderr,"R27H20_GUEST_RECOVERY_PROOF_UNTRUSTED=RED",err)
  os.Exit(1)
 }
}
