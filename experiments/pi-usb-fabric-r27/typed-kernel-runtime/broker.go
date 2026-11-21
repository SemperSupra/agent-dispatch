//go:build ignore

// R18 disposable host-only bridge. Uses EXISTING blue.Manager and heldledger,
// not another controller. It admits live USB/IP B only after independently
// observed Linux guest UART/evdev evidence and original typed A kernel release.
// B's final state stays HELD until separately authenticated release.
// Neither UART text nor this PUBLIC test MAC is production guest attestation.
package main

import (
 "bufio"
 "bytes"
 "crypto/ed25519"
 "encoding/json"
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
 guestsign "example.org/usb-fabric-r22-guest-ed25519"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)

var pendingGuest=errors.New("R27 pending independent guest/kernel release authority")
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
  // R27-G: consumer A is a LINUX KERNEL VHCI USBIP endpoint, not a
  // QMP-owned native keyboard. Preserve release-intent, NEVER use QMP
  // ACK for A. B's final TEST-ONLY cleanup still uses old simulated
  // QMP stage and is explicitly NOT a qualifying signed B kernel release.
  // Both A and B are kernel-owned USB/IP VHCI inputs. Never fabricate
  // a QMP-native release ACK for either endpoint. B without its own
  // independently signed kernel UP must remain held/quarantined.
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
// Qualify two actual Linux USBIP guest KEY_A evdev events that are signed
// INSIDE consumer A's disposable QEMU kernel. The first public key is TOFU,
// so this cannot establish a protected guest identity in production.
func observeSignedGuest(path string,deadline time.Time)(evidence.Event,evidence.Event,ed25519.PublicKey,[32]byte,error){
 var zero [32]byte
 nonceRaw,err:=hex.DecodeString(os.Getenv("R22_CHALLENGE"))
 if err!=nil||len(nonceRaw)!=32{return evidence.Event{},evidence.Event{},nil,zero,errors.New("missing host supplied guest challenge")}
 var nonce [32]byte;copy(nonce[:],nonceRaw)
 conn,err:=dial(path,deadline);if err!=nil{return evidence.Event{},evidence.Event{},nil,zero,err}
 defer conn.Close()
 if err=conn.SetReadDeadline(deadline);err!=nil{return evidence.Event{},evidence.Event{},nil,zero,err}
 reader:=json.NewDecoder(bufio.NewReader(conn))
 var pub ed25519.PublicKey
 events:=make([]evidence.Event,0,2)
 for i:=0;i<2;i++{
  var raw struct{
   evidence.Event
   GuestPub string `json:"r22_pub"`
   GuestSignature string `json:"r22_sig"`
  }
  if err=reader.Decode(&raw);err!=nil{return evidence.Event{},evidence.Event{},nil,zero,fmt.Errorf("signed guest receipt %d missing: %w",i,err)}
  e:=raw.Event
  if e.Scope!=guestwire.Scope() || e.Source!="guest.evdev" ||
   e.KeyCode!="key-a" || e.Down!=(i==0) || e.EventSequence==0 {
   return evidence.Event{},evidence.Event{},nil,zero,errors.New("wrong signed guest scope or event order")
  }
  next,decodeErr:=hex.DecodeString(raw.GuestPub)
  if decodeErr!=nil||len(next)!=ed25519.PublicKeySize{return evidence.Event{},evidence.Event{},nil,zero,errors.New("invalid guest public key")}
  if i==0{pub=append(ed25519.PublicKey(nil),next...)
  }else if !bytes.Equal(pub,next){return evidence.Event{},evidence.Event{},nil,zero,errors.New("guest key swapped mid-lease")}
  e.Proof=raw.GuestSignature
  if !guestsign.VerifyWithPinnedPublicKey(e,nonce,pub){
   return evidence.Event{},evidence.Event{},nil,zero,errors.New("guest-origin Ed25519 event rejected")
  }
  events=append(events,e)
 }
 if events[1].EventSequence<=events[0].EventSequence{return evidence.Event{},evidence.Event{},nil,zero,errors.New("replayed guest up event")}
 return events[0],events[1],pub,nonce,nil
}
func run()error{
 if len(os.Args)!=5 {return errors.New("usage r18-broker provider-log A-log B-log provider-serial-socket")}
 p,a,b,socket:=os.Args[1],os.Args[2],os.Args[3],os.Args[4]
 deadline:=time.Now().Add(255*time.Second)
 rawPreapproved,err:=os.ReadFile("/guest/r27-approved-public.hex")
 if err!=nil{return fmt.Errorf("missing host pre-approved test public key: %w",err)}
 preapproved,err:=hex.DecodeString(strings.TrimSpace(string(rawPreapproved)))
 if err!=nil||len(preapproved)!=ed25519.PublicKeySize{
  return errors.New("invalid preboot pinned test public key")
 }
 fmt.Println("R27_B_HOST_PUB_PIN_READY_BEFORE_CONSUMER_A_QEMU_BOOT=PASS")
 c,err:=dial(socket,deadline)
 if err!=nil{return err}
 defer c.Close()
 // Host connects directly to the first guest's virtio-serial receipt port;
 // TCP clients cannot provide or alter this QEMU-local test wire.
 signedDown,signedUp,pinnedGuestPub,hostNonce,err:=observeSignedGuest("/tmp/r22-consumer-a-guest.sock",deadline)
 if err!=nil{return err}
 if !bytes.Equal(pinnedGuestPub,preapproved) {
  return errors.New("R27-B real Linux USBIP guest signer mismatched preapproved host key")
 }
 fmt.Println("R27_B_REAL_USBIP_VHCI_GUEST_PREBOOT_HOST_KEY_MATCH=PASS")
 fmt.Println("R22_B_REAL_USBIP_CONSUMER_A_IN_GUEST_ED25519_VERIFIED=PASS")
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
 // R27-T: protected, host-owned journal root for the R27-S recovered
 // startup API. This disposable three-QEMU experiment runs on an isolated
 // /tmp tmpfs; a real deployment MUST pin a durable protected host path.
 const journalRoot="/tmp/r27-t-host-ledger"
 if err=os.Mkdir(journalRoot,0700);err!=nil{return fmt.Errorf("R27_T_JOURNAL_ROOT_CREATE: %w",err)}
 rootInfo,rootErr:=os.Lstat(journalRoot)
 if rootErr!=nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()!=0700 {
  return errors.New("R27_T_HOST_JOURNAL_ROOT_NOT_PRIVATE")
 }
 journal:=heldledger.Store{Path:journalRoot+"/held.json"}
 m:=blue.New("keyboard","xhci0/auto",&journalExecutor{s:journal})
 leaseA,err:=m.Reserve("consumer-A","keyboard","xhci0/auto")
 if err!=nil{return err}
 if err=m.Attach(leaseA);err!=nil{return err}
 if err=m.Input(leaseA,"key-a-down");err!=nil{return err}
 if _,err=m.Reserve("consumer-B","keyboard","xhci0/auto");!errors.Is(err,blue.ErrUnavailable){
  return fmt.Errorf("R18_B_RESERVE_ADMITTED_WHILE_A_ATTACHED=%v",err)
 }
 if err=m.Revoke(leaseA);!errors.Is(err,pendingGuest){
  return fmt.Errorf("R27_G_A_REAL_KERNEL_RELEASE_PENDING=%v",err)
 }
 state,err:=journal.Read()
 if err!=nil||state.Sequence!=1||!state.Held||state.ReleasePhase!="release-intent"{
  return fmt.Errorf("R27_G_A_NOT_DURABLY_HELD_IN_RELEASE_INTENT %+v %v",state,err)
 }
 fmt.Println("R27_G_A_NO_QMP_NATIVE_ACK_UNTIL_LINUX_KERNEL_ISOLATED=PASS")
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
 // The provider may already have received the untrusted TCP A_DETACHED
 // signal, but it MUST block on its independent HOST-ONLY serial channel.
 if err=wait(a,deadline,"R11_CONSUMER_A_ACTUAL_VHCI_QUIESCENT=PASS",
  "R11_CONSUMER_A_RELEASE_RECEIPT_SENT=PASS");err!=nil{return err}
 if err=wait(p,deadline,"R11_PROVIDER_A_DETACH_CONFIRMED_BEFORE_B_RETRY=PASS",
  "R18_PROVIDER_HOST_SERIAL_GATE_WAITING=PASS");err!=nil{return err}
 if strings.Contains(read(p),"R11_PROVIDER_B_RETRY_AUTHORIZED=PASS"){
  return errors.New("R18_PROVIDER_ALREADY_AUTHORIZED_B_BEFORE_GO_GATE")
 }
 // Require the existing real Linux provider and consumer-B's separate
 // kernel raw-import refusal, plus QMP PCIGraph read-only VM provenance.
 // These are verified TEST-ONLY serial/host-process witnesses, NOT yet
 // privileged authenticated host kernel/sysfs sensors.
 if err=wait(p,deadline,
  "R27_A_PROVIDER_REAL_CONFIGFS_UDC_UNBOUND_BEFORE_A_DETACH=PASS",
  "R27_A_REAL_RAW_B_LATE_IMPORT_DENIED_BEFORE_HOST_GRANT=PASS");err!=nil{return err}
 if err=wait(b,deadline,
  "R27_A_B_LATE_RAW_USBIP_IMPORT_DENIED_WHILE_UNBOUND=PASS");err!=nil{return err}
 if err=wait("/tmp/r26-qmp-pci.log",deadline,
  "R26_A_UPSTREAM_QMP_PCI_GRAPH_OBSERVED=PASS");err!=nil{return err}
 // TEST-ONLY bridge signs claim AFTER independent real event/port inspection;
 // production must instead authenticate actual guest source, QMP ACK, scope.
 // Bind the *observed* current guest's real Ed25519 up to the existing
 // durable Go Manager lease decision. The guest's default R26 test scope
 // does not cryptographically bind the dynamic blue.Lease, so production
 // attestation and R26 real QMP remain NOT_TESTED.
 good:=claim(leaseA,1,signedDown.EventSequence,signedUp.EventSequence)
 good.Proof=signedUp.Proof
 signedVerifier:=func(c heldledger.ReleaseClaim)bool{
  return c==good &&
   guestsign.VerifyWithPinnedPublicKey(signedDown,hostNonce,pinnedGuestPub) &&
   guestsign.VerifyWithPinnedPublicKey(signedUp,hostNonce,pinnedGuestPub)
 }
 // Original Go heldledger + blue.Manager from exact R27-D source. No
 // second manager or QMP actuator; host claim binds the SAME current
 // signed DOWN and UP and the existing blue.Lease to real lab witnesses.
 witness:=heldledger.KernelIsolationClaim{
  VMIncarnation:"qemu-consumer-a:d2e44f29-6a7b-44a9-8e16-49f351e22881",
  GuestID:good.GuestID,DeviceID:good.DeviceID,
  HostEpoch:good.HostEpoch,GuestEpoch:good.GuestEpoch,
  LeaseEpoch:leaseA.Epoch,Generation:leaseA.Generation,
  ReleaseSequence:1,
  GuestDownEventSequence:signedDown.EventSequence,
  GuestUpEventSequence:signedUp.EventSequence,
  ExporterBusID:"usbip-vudc.0",
  ConsumerVHCIPort:"vhci_hcd/port0",
  ProviderUDCUnbound:true,ConsumerVHCIQuiescent:true,
 }
 hostSensor:=func(k heldledger.KernelIsolationClaim)bool{
  // These are INDEPENDENT source programs but UNTRUSTED QEMU guest
  // serial/test callbacks. This method MUST NOT be used as production
  // identity or kernel isolation proof.
  return k==witness &&
   strings.Contains(read(p),"R27_A_PROVIDER_REAL_CONFIGFS_UDC_UNBOUND_BEFORE_A_DETACH=PASS") &&
   strings.Contains(read(a),"R11_CONSUMER_A_ACTUAL_VHCI_QUIESCENT=PASS") &&
   strings.Contains(read(b),"R27_A_B_LATE_RAW_USBIP_IMPORT_DENIED_WHILE_UNBOUND=PASS") &&
   strings.Contains(read("/tmp/r26-qmp-pci.log"),"R26_A_UPSTREAM_QMP_PCI_GRAPH_OBSERVED=PASS")
 }
 stage,stageErr:=journal.AcknowledgeKernelIsolation(1,witness,hostSensor)
 if stageErr!=nil||!stage.Held||stage.ReleasePhase!="kernel-isolated"||len(stage.KernelWitnessHash)!=64{
  return fmt.Errorf("R27_G_ORIGINAL_KERNEL_ISOLATION_FSYNC_FAIL: %+v %v",stage,stageErr)
 }
 fmt.Println("R27_G_ORIGINAL_GO_KERNEL_ISOLATION_STAGE_FSYNCED=PASS")
 if err=m.RestoreAfterVerifiedKernelUp(journal,1,witness,hostSensor,good,signedVerifier);err!=nil{return err}
 fmt.Println("R27_G_ORIGINAL_MANAGER_SIGNED_CURRENT_DOWN_UP_UNLOCKED_B=PASS")
 fmt.Println("R22_B_GUEST_ORIGIN_ED25519_DURABLE_HELD_RELEASE=PASS")
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
 // R27-L: host socket creation/write does not prove receipt by the
 // independently running Linux provider. Read exact READY from its UART,
 // issue allow only after original Go kernel isolation fsync, and demand
 // exact post-UDC-rebind ACK. This channel remains test-only, not attested.
 if e:=c.SetDeadline(time.Now().Add(35*time.Second));e!=nil{return e}
 uart:=bufio.NewReader(c)
 readyLine,e:=uart.ReadString('\n')
 if e!=nil||strings.TrimSuffix(strings.TrimSuffix(readyLine,"\n"),"\r")!="READY R27-L"{
  return fmt.Errorf("R27_L_GUEST_UART_READY_MISSING_OR_INVALID line=%q err=%v",readyLine,e)
 }
 fmt.Println("R27_L_HOST_OBSERVED_ACTUAL_PROVIDER_UART_READY=PASS")
 if _,err=c.Write([]byte("ALLOW_B R27-L\n"));err!=nil{return err}
 fmt.Println("R18_EXISTING_GO_BROKER_GRANTED_HOST_SERIAL_B_AFTER_FSYNC=PASS")
 ackLine,e:=uart.ReadString('\n')
 if e!=nil||strings.TrimSuffix(strings.TrimSuffix(ackLine,"\n"),"\r")!="ACK R27-L"{
  return fmt.Errorf("R27_L_GUEST_UART_POST_UDC_ACK_MISSING_OR_INVALID line=%q err=%v",ackLine,e)
 }
 fmt.Println("R27_L_HOST_RECEIVED_ACTUAL_PROVIDER_POST_UDC_ACK=PASS")
 if err=wait(p,deadline,"R27_L_PROVIDER_REAL_UDC_REBOUND_BEFORE_UART_ACK=PASS","R18_PROVIDER_B_RETRY_AFTER_HOST_GATE=PASS");err!=nil{return err}
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
 // B's *actual* kernel HID events were observed, but it has NO second
 // in-guest Ed25519 release receipt nor separately verified kernel-isolation
 // witness. Keep the original heldledger release-intent, even on clean
 // process exit, rather than invoking QMP-native ACK for a Linux VHCI input.
 beforeB,err:=journal.Read()
 if err!=nil||!beforeB.Held||beforeB.Sequence!=3||beforeB.ReleasePhase!="release-intent"{
  return fmt.Errorf("R27_I_B_NOT_HELD_IN_RELEASE_INTENT %+v %v",beforeB,err)
 }
 frozenB,err:=os.ReadFile(journal.Path);if err!=nil{return err}
 if err=m.RestoreAfterVerifiedGuestUp(journal,3,claim(leaseA,1,10,11),verifier(leaseA));!errors.Is(err,heldledger.ErrUnverified){
  return fmt.Errorf("R27_I_STALE_A_RELEASE_ADMITTED_FOR_B=%v",err)
 }
 if err=m.RestoreAfterVerifiedGuestUp(journal,3,claim(leaseB,3,12,13),verifier(leaseB));!errors.Is(err,heldledger.ErrUnverified){
  return fmt.Errorf("R27_I_TEST_MAC_ONLY_B_RELEASE_ADMITTED=%v",err)
 }
 afterBytes,err:=os.ReadFile(journal.Path)
 if err!=nil||!bytes.Equal(frozenB,afterBytes){
  return errors.New("R27_I_INVALID_B_PROOF_MUTATED_DURABLE_HELD")
 }
 final,err:=journal.Read()
 if err!=nil||!final.Held||final.Sequence!=3||final.ReleasePhase!="release-intent"{
  return fmt.Errorf("R27_I_FINAL_B_HELD_STATE_LOST %+v %v",final,err)
 }
 if _,err=m.Reserve("consumer-C","keyboard","xhci0/auto");!errors.Is(err,blue.ErrQuarantined){
  return fmt.Errorf("R27_I_CONSUMER_C_ADMITTED_WITHOUT_B_KERNEL_RELEASE=%v",err)
 }
 // R27-T: in the same exact actual 3-Linux-QEMU-kernel handoff, prove
 // a fresh R27-S host owner cannot restart/admit with original B still
 // durably HELD in release-intent. No B proof is manufactured or journal
 // cleared. Original Go Manager remains sole live control authority.
 frozenRecovery,err:=os.ReadFile(journal.Path);if err!=nil{return err}
 restart,owner,restartErr:=blue.NewAfterExclusiveDurableAdmission(
  "keyboard","xhci0/auto",&journalExecutor{s:journal},journal)
 if owner!=nil{
  _=owner.Close()
  return errors.New("R27_T_RECOVERED_OWNER_ACQUIRED_WHILE_B_HELD")
 }
 if !errors.Is(restartErr,blue.ErrQuarantined){
  return fmt.Errorf("R27_T_B_HELD_RESTART_NOT_QUARANTINED=%v",restartErr)
 }
 if restart!=nil{
  if _,e:=restart.Reserve("consumer-C","keyboard","xhci0/auto");
   !errors.Is(e,blue.ErrQuarantined){
   return fmt.Errorf("R27_T_RECOVERED_MANAGER_ADMITTED_C=%v",e)
  }
 }
 afterRecovery,err:=os.ReadFile(journal.Path)
 if err!=nil||!bytes.Equal(frozenRecovery,afterRecovery){
  return errors.New("R27_T_UNVERIFIED_RESTART_MUTATED_DURABLE_B_HELD")
 }
 fmt.Println("R27_T_REAL_3_KERNEL_B_HELD_RESTART_OWNER_QUARANTINED=PASS")
 fmt.Println("R27_T_RECOVERY_REFUSAL_JOURNAL_BYTE_IDENTICAL=PASS")
 fmt.Println("R27_T_CLEAN_FIRST_BOOT_RUNTIME_OWNER_MIGRATION=NOT_TESTED")
 fmt.Println("R27_T_LIVE_QEMU_SIGKILL_VHCI_RESTART=NOT_TESTED")
 fmt.Println("R27_I_NO_FAKE_QMP_ACK_FOR_LINUX_VHCI_B=PASS")
 fmt.Println("R27_I_TEST_ONLY_B_RELEASE_PROOF_REJECTED_JOURNAL_BYTE_IDENTICAL=PASS")
 fmt.Println("R27_I_B_DURABLE_HELD_RELEASE_INTENT_AFTER_REAL_HID=PASS")
 fmt.Println("R27_I_CONSUMER_C_DENIED_UNTIL_INDEPENDENT_B_RELEASE=PASS")
 fmt.Println("R27_I_GUEST_SIGNED_B_KERNEL_RELEASE=NOT_TESTED")
 fmt.Println("R27_G_PRIVILEGED_HOST_KERNEL_SENSORS=NOT_TESTED")
 fmt.Println("R27_G_DYNAMIC_BLUE_LEASE_SIGNED_IN_GUEST=NOT_TESTED")
 fmt.Println("R18_B_ACTUAL_KERNEL_EVDEV_AFTER_GO_B_GATE=PASS")
 fmt.Println("R18_STALE_A_PROOF_DENIED_AND_B_HELD_QUARANTINED=PASS")
 fmt.Println("R18_EXISTING_GO_MANAGER_CONTROLLED_REAL_USBIP_B_TRIGGER=PASS")
 fmt.Println("R22_B_SIGNED_GUEST_A_PROOF_TO_REAL_CONFIGFS_VUDC_REBIND=PASS")
 fmt.Println("R27_B_PREBOOT_HOSTPIN_REAL_LINUX_USBIP_A_TO_B=PASS")
 fmt.Println("R27_B_SIGNED_DYNAMIC_BLUE_LEASE_SCOPE_IN_GUEST=NOT_TESTED")
 fmt.Println("R27_B_HARDWARE_GUEST_IDENTITY_ROOT=NOT_TESTED")
 fmt.Println("R18_PRODUCTION_GUEST_ATTESTATION_AND_REAL_QMP=NOT_TESTED")
 fmt.Println("R22_B_DYNAMIC_LEASE_SCOPE_SIGNED_GUEST_ATTESTATION_AND_REAL_QMP=NOT_TESTED")
 return nil
}
func main(){
 if err:=run();err!=nil{fmt.Fprintf(os.Stderr,"R18_CROSS_KERNEL_HOST_GO_GATE=RED: %v\n",err);os.Exit(42)}
}
