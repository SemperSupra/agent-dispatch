//go:build r22_guest

// Synthetic TEST-ONLY Linux guest evdev sensor. It emits only signed key
// transitions over a virtio-serial character device, NOT host serial console.
// This key is public; no production authentication or real USB/IP implied.
package main

import (
 "crypto/ed25519"
 "encoding/hex"
 "strings"
 "encoding/binary"
 "encoding/json"
 "fmt"
 "bufio"
 "path/filepath"
 "time"
 "io"
 "os"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)

type inputEvent struct {
 Sec int64
 Usec int64
 Type uint16
 Code uint16
 Value int32
}

func run()error {
 if len(os.Args)!=3 && !(len(os.Args)==4 && os.Args[3]=="scoped"){return fmt.Errorf("need /dev/input/eventN virtio-port [scoped]")}
 ev,err:=os.Open(os.Args[1]);if err!=nil{return err}
 defer ev.Close()
 scoped:=len(os.Args)==4 && os.Args[3]=="scoped"
 mode:=os.O_WRONLY
 if scoped{mode=os.O_RDWR}
 wire,err:=os.OpenFile(os.Args[2],mode,0);if err!=nil{return err}
 defer wire.Close()
 // R26-B TEST-ONLY pre-enrollment: a random disposable key is placed
 // in this guest initrd at BUILD time and its PUBLIC half is independently
 // pinned on the host BEFORE this VM boots. This proves enrollment ordering
 // only. The host controls the image and can extract its seed; NOT hardware
 // attestation, protected guest secrets, or production authorization.
 rawSeed,err:=os.ReadFile("/guest/r26-test-ed25519-seed.hex")
 if err!=nil{return fmt.Errorf("r26 preprovisioned guest seed missing: %w",err)}
 seed,err:=hex.DecodeString(strings.TrimSpace(string(rawSeed)))
 if err!=nil||len(seed)!=ed25519.SeedSize{return fmt.Errorf("invalid ephemeral guest seed")}
 private:=ed25519.NewKeyFromSeed(seed)
 pub:=private.Public().(ed25519.PublicKey)
 rawCmd,err:=os.ReadFile("/proc/cmdline");if err!=nil{return err}
 var challenge [32]byte
 found:=false
 for _,arg:=range strings.Fields(string(rawCmd)){
  if strings.HasPrefix(arg,"r22_challenge="){
   b,e:=hex.DecodeString(strings.TrimPrefix(arg,"r22_challenge="))
   if e!=nil||len(b)!=32{return fmt.Errorf("R22 test challenge invalid")}
   copy(challenge[:],b);found=true
  }
 }
 if !found||challenge==([32]byte{}){return fmt.Errorf("R22 challenge not provided by host")}
 fmt.Println("R26_B_TEST_SEED_PREPROVISIONED_IN_GUEST_INITRD=PASS")
 fmt.Println("R24_B_GUEST_PUBLIC_KEY="+hex.EncodeToString(pub))

 encoder:=json.NewEncoder(wire)
 reader:=json.NewDecoder(bufio.NewReader(wire))
 fmt.Println("R26_L8_REAL_GUEST_VIRTIO_EVDEV_OBSERVER_READY=PASS")
 seenDown:=false
 cycle:=0
 scope:=guestwire.Scope()
 var lastUp evidence.Event
 bind:=func()error{
  var msg struct{
   Op string
   Scope releasegate.Scope
  }
  if err:=reader.Decode(&msg);err!=nil{return fmt.Errorf("scope read: %w",err)}
  if msg.Op!="bind"||msg.Scope.GuestID!=guestwire.Scope().GuestID||
   msg.Scope.DeviceID!=guestwire.Scope().DeviceID||
   msg.Scope.HostEpoch==""||msg.Scope.GuestEpoch==""||
   msg.Scope.LeaseEpoch==""||msg.Scope.Generation==0||
   msg.Scope.ReleaseSequence==0{
   return fmt.Errorf("scope message invalid")
  }
  scope=msg.Scope
  fmt.Println("R26_L9C_GUEST_PER_LEASE_SCOPE_BOUND=PASS")
  return nil
 }
 if scoped {
  if err:=bind();err!=nil{return err}
 }
 for i:=0;i<200000;i++{
  var e inputEvent
  if err:=binary.Read(ev,binary.LittleEndian,&e);err!=nil{
   if err==io.EOF{return fmt.Errorf("evdev disconnected before key up")}
   return err
  }
  if e.Type!=1||e.Code!=30 {continue} // EV_KEY, Linux KEY_A
  down:=e.Value==1
  if !down && (!seenDown||e.Value!=0){continue}
  if down && seenDown {continue}
  seq:=uint64(10+2*cycle)
  if !down{seq=uint64(11+2*cycle)}
  receipt:=guestwire.SignForSyntheticGuest(evidence.Event{
   Scope:scope,Source:"guest.evdev",KeyCode:"key-a",
   Down:down,EventSequence:seq,
  })
  // Keep the original R26 public test MAC event for inherited R26 gates.
  // Append a SEPARATE Ed25519 proof generated from real in-guest evdev
  // receipt, scoped to the host-supplied per-run challenge.
  clear:=receipt;clear.Proof=""
  signingWire,err:=json.Marshal(struct{
   Domain string
   Event evidence.Event
   Challenge [32]byte
  }{Domain:"USB-FABRIC-R22-TEST-ONLY-ED25519-v1",Event:clear,Challenge:challenge})
  if err!=nil{return err}
  body,err:=json.Marshal(receipt);if err!=nil{return err}
  var message map[string]any
  if err=json.Unmarshal(body,&message);err!=nil{return err}
  message["r22_pub"]=hex.EncodeToString(pub)
  message["r22_sig"]=hex.EncodeToString(ed25519.Sign(private,signingWire))
  if err:=encoder.Encode(message);err!=nil{return err}
  fmt.Println("R22_A_REAL_GUEST_EVDEV_EVENT_ED25519_SIGNED=PASS")
  if down {
   seenDown=true
   fmt.Println("R26_L8_REAL_GUEST_VIRTIO_EVDEV_DOWN_SENT=PASS")
   if cycle==1{if scoped{fmt.Println("R26_L9C_SECOND_ACTUAL_GUEST_EVDEV_DOWN=PASS")}else{fmt.Println("R26_L9B_SECOND_ACTUAL_GUEST_EVDEV_DOWN=PASS")}}
  }else{
   fmt.Println("R26_L8_REAL_GUEST_VIRTIO_EVDEV_UP_SENT=PASS")
   if cycle==1{if scoped{fmt.Println("R26_L9C_SECOND_ACTUAL_GUEST_EVDEV_UP=PASS")}else{fmt.Println("R26_L9B_SECOND_ACTUAL_GUEST_EVDEV_UP=PASS")}}
   lastUp=receipt
   cycle++
   if cycle>=2{
    if scoped {
     // Independent Linux sysfs proof of actual keyboard removal, not
     // a signed event or host-authorized lease release.
     devPath:="/sys/class/input/"+filepath.Base(os.Args[1])
     for j:=0;j<200;j++{
      if _,err:=os.Stat(devPath);os.IsNotExist(err){
       fmt.Println("R26_L9C_GUEST_SYSFS_KEYBOARD_DETACHED=PASS")
       return nil
      }
      time.Sleep(100*time.Millisecond)
     }
     return fmt.Errorf("keyboard still present in guest sysfs after detach")
    }
    return nil
   }
   seenDown=false
   if scoped{
    if err:=bind();err!=nil{return err}
    // Falsifier: repeat the prior real UP event with its old signed
    // first-lease scope; host MUST reject despite a valid test-only MAC.
    if err:=encoder.Encode(lastUp);err!=nil{return err}
    fmt.Println("R26_L9C_GUEST_REPLAYED_OLD_SCOPE_SENT=PASS")
   }
  }
 }
 return fmt.Errorf("evdev observation bound exceeded")
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"R26_L8_GUEST_OBSERVER=RED",err);os.Exit(1)}
}
