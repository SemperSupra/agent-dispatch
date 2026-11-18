// R18 disposable host-only bridge. Uses EXISTING blue.Manager and heldledger,
// not another controller. It admits live USB/IP B only after independently
// observed Linux guest UART/evdev evidence AND a test-only signed journal release.
// Neither UART text nor this PUBLIC test MAC is production guest attestation.
package main

import (
 "bytes"
 "crypto/hmac"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "net"
 "os"
 "path/filepath"
 "strings"
 "time"

 "example.org/usb-fabric-r26-integrated/blue"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

var pendingGuest=errors.New("R18 TEST-ONLY QMP ACK pending independent evdev")
var publicKey=[]byte("R18-PUBLIC-TEST-ONLY-NO-PRODUCTION-AUTH")
type journalExecutor struct{ s heldledger.Store }
func(e *journalExecutor)Input(command string)error {
 st,err:=e.s.Read();if err!=nil{return err}
 switch command{
 case "key-a-down":
  if st.Held{return blue.ErrDenied}
  _,err=e.s.Transition(st.Sequence,true)
  return err
 case "key-a-up":
  if !st.Held{return blue.ErrDenied}
  if st.ReleasePhase==""{
   if _,err=e.s.RequestRelease(st.Sequence);err!=nil{return err}
  }
  if _,err=e.s.AcknowledgeQMPRelease(st.Sequence);err!=nil{return err}
  return pendingGuest
 default:return blue.ErrDenied
 }
}
func(e *journalExecutor)ReleaseAll()error{return e.Input("key-a-up")}

func mac(c heldledger.ReleaseClaim)string{
 h:=hmac.New(sha256.New,publicKey)
 _,_=fmt.Fprintf(h,"%s|%s|%s|%s|%s|%d|%d|%d|%d|%s|%s|%t",
  c.GuestID,c.DeviceID,c.HostEpoch,c.GuestEpoch,c.LeaseEpoch,
  c.Generation,c.ReleaseSequence,c.DownEventSequence,c.EventSequence,
  c.Source,c.Key,c.KeyReleased)
 return hex.EncodeToString(h.Sum(nil))
}
func claim(l blue.Lease,seq,down,up uint64)heldledger.ReleaseClaim{
 c:=heldledger.ReleaseClaim{
  GuestID:"R18-QEMU-TEST-ONLY",DeviceID:l.Device,HostEpoch:"R18-host",
  GuestEpoch:"R18-guest",LeaseEpoch:l.Epoch,Generation:l.Generation,
  ReleaseSequence:seq,DownEventSequence:down,EventSequence:up,
  Source:"guest.evdev",Key:heldledger.KeyA,KeyReleased:true,
 }
 c.Proof=mac(c);return c
}
func verifier(l blue.Lease)heldledger.ReleaseVerifier{
 return func(c heldledger.ReleaseClaim)bool{
  if c.GuestID!="R18-QEMU-TEST-ONLY"||c.GuestEpoch!="R18-guest"||
    c.HostEpoch!="R18-host"||c.DeviceID!=l.Device||
    c.LeaseEpoch!=l.Epoch||c.Generation!=l.Generation||
    c.Source!="guest.evdev"||c.Key!=heldledger.KeyA||!c.KeyReleased{
   return false
  }
  got,e:=hex.DecodeString(c.Proof);if e!=nil{return false}
  want,e:=hex.DecodeString(mac(c));return e==nil&&hmac.Equal(got,want)
 }
}
func read(path string)string{
 b,_:=os.ReadFile(path);return string(b)
}
func wait(path string,deadline time.Time, markers ...string)error{
 for time.Now().Before(deadline) {
  t:=read(path)
  ready:=true
  for _,m:=range markers {
   if !strings.Contains(t,m){ready=false;break}
  }
  if ready{return nil}
  time.Sleep(100*time.Millisecond)
 }
 return fmt.Errorf("R18_MARKERS_TIMEOUT path=%s missing from %v",filepath.Base(path),markers)
}
func dial(path string,deadline time.Time)(net.Conn,error){
 for time.Now().Before(deadline){
  c,err:=net.DialTimeout("unix",path,time.Second)
  if err==nil{return c,nil}
  time.Sleep(100*time.Millisecond)
 }
 return nil,errors.New("R18_QEMU_HOST_SERIAL_SOCKET_UNREACHABLE")
}
func must(x bool,format string,args ...any){
 if !x{fmt.Fprintf(os.Stderr,"R18_RED "+format+"\n",args...);os.Exit(51)}
}
func run()error{
 if len(os.Args)!=5 {return errors.New("usage r18-broker provider-log A-log B-log provider-serial-socket")}
 p,a,b,socket:=os.Args[1],os.Args[2],os.Args[3],os.Args[4]
 deadline:=time.Now().Add(175*time.Second)
 c,err:=dial(socket,deadline)
 if err!=nil{return err}
 defer c.Close()
 fmt.Println("R18_HOST_ONLY_QEMU_ISA_SERIAL_CHANNEL=PASS")
 // These are actual guest-kernel evdev observations in a disposable lab,
 // but UART reports are not cryptographically authenticated receipts.
 if err=wait(a,deadline,
  "R08_CONSUMER_REAL_REMOTE_HID_DATA=PASS",
  "USBFABRIC_R06_REAL_KEY_A_DOWN=PASS",
  "USBFABRIC_R06_REAL_KEY_A_UP=PASS");err!=nil{return err}
 if err=wait(b,deadline,
  "R10_CONSUMER_B_CROSS_KERNEL_DUPLICATE_DENIED=PASS",
  "R10_CONSUMER_B_NO_GHOST_VHCI=PASS");err!=nil{return err}
 fmt.Println("R18_TWO_INDEPENDENT_QEMU_KERNEL_EVDEV_AND_BUSY_OBSERVED=PASS")
 journal:=heldledger.Store{Path:"/tmp/r18-held-ledger.json"}
 m:=blue.New("keyboard","xhci0/auto",&journalExecutor{s:journal})
 leaseA,err:=m.Reserve("consumer-A","keyboard","xhci0/auto")
 if err!=nil{return err}
 if err=m.Attach(leaseA);err!=nil{return err}
 if err=m.Input(leaseA,"key-a-down");err!=nil{return err}
 if _,err=m.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,blue.ErrUnavailable){
  return fmt.Errorf("R18_B_RESERVE_ADMITTED_WHILE_A_ATTACHED=%v",err)
 }
 if err=m.Revoke(leaseA);!errors.Is(err,pendingGuest){
  return fmt.Errorf("R18_TEST_ONLY_QMP_ACK_INCOMPLETE=%v",err)
 }
 state,err:=journal.Read()
 if err!=nil||state.Sequence!=1||!state.Held||state.ReleasePhase!="qmp-acked"{
  return fmt.Errorf("R18_HELD_AND_ACK_EXPECTED %+v %v",state,err)
 }
 fmt.Println("R18_TEST_ONLY_QMP_ACK_HELD_QUARANTINE=PASS")
 pre,err:=os.ReadFile(journal.Path);if err!=nil{return err}
 fake:=claim(leaseA,1,10,11)
 fake.Source="usbip.detach";fake.Proof=mac(fake)
 if err=m.RestoreAfterVerifiedGuestUp(journal,1,fake,verifier(leaseA));!errors.Is(err,heldledger.ErrUnverified){
  return fmt.Errorf("R18_TRANSPORT_ONLY_RELEASE_ADMITTED=%v",err)
 }
 post,err:=os.ReadFile(journal.Path)
 if err!=nil||!bytes.Equal(pre,post){return errors.New("R18_HELD_JOURNAL_MODIFIED_BY_TRANSPORT")}
 if _,err=m.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,blue.ErrQuarantined){
  return fmt.Errorf("R18_EARLY_B_ADMISSION=%v",err)
 }
 fmt.Println("R18_GUEST_TRANSPORT_SIGNAL_NOT_AUTHORIZED_FOR_REASSIGNMENT=PASS")
 // Wait until the provider has *actually opened* the secondary guest
 // serial receiver. QEMU's ISA UART is NOT a buffered message queue,
 // so writing before the guest reads can discard this command.
 if err=wait(p,deadline,"R19_PROVIDER_TEST_HOST_PREPARATION_WAIT=PASS");err!=nil{return err}
 fmt.Println("R19_HOST_CONFIRMED_PROVIDER_SERIAL_RECEIVER_READY=PASS")
 if err=c.SetWriteDeadline(time.Now().Add(5*time.Second));err!=nil{return err}
 if _,err=c.Write([]byte("PREPARE_BYPASS\n"));err!=nil{return err}
 fmt.Println("R19_HOST_GO_LEDGER_HELD_BEFORE_UNTRUSTED_CLIENT_PROBE=PASS")
 // The provider may already have received the untrusted TCP A_DETACHED
 // signal, but it MUST block on its independent HOST-ONLY serial channel.
 if err=wait(a,deadline,"R11_CONSUMER_A_ACTUAL_VHCI_QUIESCENT=PASS",
  "R11_CONSUMER_A_RELEASE_RECEIPT_SENT=PASS");err!=nil{return err}
 if err=wait(p,deadline,"R11_PROVIDER_A_DETACH_CONFIRMED_BEFORE_B_RETRY=PASS",
  "R18_PROVIDER_HOST_SERIAL_GATE_WAITING=PASS");err!=nil{return err}
 if err=wait(b,deadline,"R19_BLUE_UNAUTHORIZED_IMPORT_BLOCKED=PASS","R19_B_DIRECT_IMPORT_PROBE_RECEIPT_SENT=PASS","R19_B_NATIVE_USBIP_LIST_RESPONDED=PASS");err!=nil{return err}
 if err=wait(p,deadline,"R19_PROVIDER_NATIVE_USBIP_BYPASS_PROBE_COMPLETE=PASS");err!=nil{return err}
 fmt.Println("R19_BLUE_BYPASS_DENIED=PASS")
 if strings.Contains(read(p),"R11_PROVIDER_B_RETRY_AUTHORIZED=PASS"){
  return errors.New("R18_PROVIDER_ALREADY_AUTHORIZED_B_BEFORE_GO_GATE")
 }
 // TEST-ONLY bridge signs claim AFTER independent real event/port inspection;
 // production must instead authenticate actual guest source, QMP ACK, scope.
 if err=m.RestoreAfterVerifiedGuestUp(journal,1,claim(leaseA,1,10,11),verifier(leaseA));err!=nil{return err}
 st,err:=journal.Read()
 if err!=nil||st.Held||st.Sequence!=2||st.LastReleaseEventSequence!=11{
  return fmt.Errorf("R18_JOURNAL_NOT_CLEAR_AFTER_SCOPED_PROOF %+v %v",st,err)
 }
 leaseB,err:=m.Reserve("consumer-B","keyboard","xhci0/auto")
 if err!=nil||leaseB.Generation<=leaseA.Generation||leaseB.Epoch!=leaseA.Epoch{
  return fmt.Errorf("R18_NEW_GENERATION_ADMISSION %+v %v",leaseB,err)
 }
 if err=m.Input(leaseA,"key-a-down");!errors.Is(err,blue.ErrDenied){
  return fmt.Errorf("R18_STALE_A_INPUT_ADMITTED=%v",err)
 }
 if err=m.Attach(leaseB);err!=nil{return err}
 // The *actual* USB/IP B import is now unblocked by the existing Go lease
 // decision, via host-only serial, NOT by a guest-controlled network string.
 if e:=c.SetWriteDeadline(time.Now().Add(5*time.Second));e!=nil{return e}
 if _,err=c.Write([]byte("ALLOW_B\n"));err!=nil{return err}
 fmt.Println("R18_EXISTING_GO_BROKER_GRANTED_HOST_SERIAL_B_AFTER_FSYNC=PASS")
 if err=wait(p,deadline,"R18_PROVIDER_B_RETRY_AFTER_HOST_GATE=PASS");err!=nil{return err}
 if err=wait(b,deadline,
  "R11_CONSUMER_B_REAL_USBIP_REASSIGNMENT=PASS",
  "R11_CONSUMER_B_INDEPENDENT_SECOND_HID_EVENTS=PASS",
  "USBFABRIC_R06_REAL_KEY_A_DOWN=PASS",
  "USBFABRIC_R06_REAL_KEY_A_UP=PASS",
  "R11_CONSUMER_B_FINAL_VHCI_QUIESCENT=PASS");err!=nil{return err}
 if err=m.Input(leaseB,"key-a-down");err!=nil{return err}
 if err=m.Revoke(leaseB);!errors.Is(err,pendingGuest){
  return fmt.Errorf("R18_B_HELD_RELEASE_PENDING_PROOF=%v",err)
 }
 if err=m.RestoreAfterVerifiedGuestUp(journal,3,claim(leaseA,1,10,11),verifier(leaseA));!errors.Is(err,heldledger.ErrUnverified){
  return fmt.Errorf("R18_REPLAYED_A_RELEASE_B_LEASE=%v",err)
 }
 if err=m.RestoreAfterVerifiedGuestUp(journal,3,claim(leaseB,3,12,13),verifier(leaseB));err!=nil{return err}
 final,err:=journal.Read()
 if err!=nil||final.Held||final.Sequence!=4||final.LastReleaseEventSequence!=13{
  return fmt.Errorf("R18_FINAL_HELD_JOURNAL %+v %v",final,err)
 }
 fmt.Println("R18_B_ACTUAL_KERNEL_EVDEV_AFTER_GO_B_GATE=PASS")
 fmt.Println("R18_STALE_A_PROOF_DENIED_AND_B_FRESH_RELEASE=PASS")
 fmt.Println("R18_EXISTING_GO_MANAGER_CONTROLLED_REAL_USBIP_B_TRIGGER=PASS")
 fmt.Println("R19_BLUE_THREE_GUEST_BROKER_NATIVE_IMPORT_PROBE=PASS")
 fmt.Println("R18_PRODUCTION_GUEST_ATTESTATION_AND_REAL_QMP=NOT_TESTED")
 return nil
}
func main(){
 if err:=run();err!=nil{fmt.Fprintf(os.Stderr,"R18_CROSS_KERNEL_HOST_GO_GATE=RED: %v\n",err);os.Exit(42)}
}
