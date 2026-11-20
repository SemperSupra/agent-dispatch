// Disposable R27-C Linux evdev sensor with host-image-provisioned Ed25519.
// The private key is embedded by a disposable image builder into initramfs:
// it is extractable from the image and NOT secure hardware attestation.
package main

import (
 "bufio"
 "crypto/ed25519"
 "encoding/binary"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "time"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/runtimeproof"
 "example.org/usb-fabric-r26-releasegate/recoveryproof"
)
type inputEvent struct{
 Sec int64
 Usec int64
 Type uint16
 Code uint16
 Value int32
}
type binding struct{
 Op string `json:"Op"`
 Scope releasegate.Scope `json:"Scope"`
 Challenge [32]byte `json:"Challenge"`
}
func run()error{
 if len(os.Args)!=3{return errors.New("need evdev node + virtio port")}
 privateBytes,err:=os.ReadFile("/etc/r27-guest-private-key")
 if err!=nil{return err}
 if len(privateBytes)!=ed25519.PrivateKeySize{return errors.New("provisioned private key has wrong length")}
 private:=ed25519.PrivateKey(privateBytes)
 ev,err:=os.Open(os.Args[1]);if err!=nil{return err}
 defer ev.Close()
 wire,err:=os.OpenFile(os.Args[2],os.O_RDWR,0);if err!=nil{return err}
 defer wire.Close()
 dec:=json.NewDecoder(bufio.NewReader(wire))
 enc:=json.NewEncoder(wire)
 binds:=make(chan binding,4)
 bindErrors:=make(chan error,1)
 go func(){
  for {
   var b binding
   if err:=dec.Decode(&b);err!=nil{
    // The QEMU host-side chardev is reconnected on actuator restart.
    // A transient EOF is not evidence of guest safety or reason to clear HELD.
    if errors.Is(err,io.EOF){
     time.Sleep(20*time.Millisecond)
     dec=json.NewDecoder(bufio.NewReader(wire))
     continue
    }
    bindErrors<-err
    return
   }
   binds<-b
  }
 }()
 validate:=func(b binding)error{
  if b.Scope.GuestID!="r26-l8-qemu-linux"||
   b.Scope.DeviceID!="usb-kbd-a"||
   b.Scope.HostEpoch==""||b.Scope.GuestEpoch==""||
   b.Scope.LeaseEpoch==""||b.Scope.Generation==0||
   b.Scope.ReleaseSequence==0||b.Challenge==([32]byte{}){
   return errors.New("invalid host guest binding")
  }
  return nil
 }
 var scope releasegate.Scope
 var challenge [32]byte
 initial:=func()error{
  var b binding
  select{
  case b=<-binds:
  case err:=<-bindErrors:return err
  }
  if b.Op!="bind"{return errors.New("initial signed lease bind absent")}
  if err:=validate(b);err!=nil{return err}
  scope=b.Scope;challenge=b.Challenge
  fmt.Println("R27C_GUEST_HOST_CHALLENGE_BOUND=PASS")
  return nil
 }
 fmt.Println("R27C_REAL_LINUX_ED25519_EVDEV_READY=PASS")
 if err:=initial();err!=nil{return err}
 type observed struct{event inputEvent;err error}
 evdev:=make(chan observed,4)
 go func(){
  for i:=0;i<250000;i++{
   var raw inputEvent
   err:=binary.Read(ev,binary.LittleEndian,&raw)
   evdev<-observed{event:raw,err:err}
   if err!=nil{return}
  }
  evdev<-observed{err:errors.New("evdev loop bounded iteration exceeded")}
 }()
 var previousUp runtimeproof.Event
 seenDown:=false
 awaitingBind:=false
 recovering:=false
 cycle:=0
 var recoveryChallenge [32]byte
 var recoverySnapshotSeq uint64
 for {
  select {
  case err:=<-bindErrors:
   return fmt.Errorf("guest host channel unavailable: %w",err)
  case b:=<-binds:
   if err:=validate(b);err!=nil{return err}
   switch b.Op {
   case "bind":
    if !awaitingBind||seenDown||recovering{return errors.New("unexpected ordinary bind while lease held")}
    scope=b.Scope;challenge=b.Challenge
    awaitingBind=false
    fmt.Println("R27C_GUEST_HOST_CHALLENGE_BOUND=PASS")
    if previousUp.EventSequence!=0{
     if err:=enc.Encode(previousUp);err!=nil{return err}
     fmt.Println("R27C_GUEST_SIGNED_PRIOR_CHALLENGE_REPLAY_SENT=PASS")
     previousUp=runtimeproof.Event{}
    }
   case "recover":
    if !seenDown||awaitingBind||recovering||b.Scope!=scope||b.Challenge==challenge{
     return errors.New("recovery bind not authorized for original held scope")
    }
    held,err:=kernelHeldKey(ev.Fd())
    if err!=nil{return fmt.Errorf("kernel recovery key-state read untrusted: %w",err)}
    if !held{return errors.New("kernel key not HELD: refuse a held-snapshot claim")}
    recoverySnapshotSeq=uint64(100+2*cycle)
    snap,err:=recoveryproof.Sign(private,recoveryproof.Event{
     Scope:scope,Challenge:b.Challenge,Phase:recoveryproof.HeldSnapshot,
     Source:"guest.evdev-state",KeyCode:"key-a",Held:true,
     EventSequence:recoverySnapshotSeq,
    })
    if err!=nil{return err}
    if err:=enc.Encode(snap);err!=nil{return err}
    recoveryChallenge=b.Challenge;recovering=true
    fmt.Println("R27H19_REAL_KERNEL_EVDEV_HELD_RECOVERY_SNAPSHOT_SIGNED=PASS")
   default:
    return errors.New("unknown guest binding operation")
   }
  case received:=<-evdev:
   if received.err!=nil{
    if errors.Is(received.err,io.EOF){return errors.New("evdev closed before completion")}
    return received.err
   }
   raw:=received.event
   if raw.Type!=1||raw.Code!=30{continue}
   down:=raw.Value==1
   if down && seenDown{continue}
   if !down && (raw.Value!=0||!seenDown){continue}
   if awaitingBind{continue}
   if recovering{
    // Only a real evdev UP event after the newly signed kernel snapshot
    // may satisfy the recovery verifier. Host QMP ACK is not guest proof.
    if down{continue}
    up,err:=recoveryproof.Sign(private,recoveryproof.Event{
     Scope:scope,Challenge:recoveryChallenge,Phase:recoveryproof.GuestKeyUp,
     Source:"guest.evdev",KeyCode:"key-a",Held:false,
     EventSequence:recoverySnapshotSeq+1,
    })
    if err!=nil{return err}
    if err:=enc.Encode(up);err!=nil{return err}
    fmt.Println("R27H19_REAL_EVDEV_RECOVERY_KEY_UP_SIGNED=PASS")
    recovering=false;seenDown=false;awaitingBind=true;cycle++
    continue
   }
   // Preserve the exact legacy two-lease signing and intentional
   // first-lease stale-UP replay proof during ordinary operation.
   seq:=uint64(10+2*cycle)
   if !down{seq=uint64(11+2*cycle)}
   event,err:=runtimeproof.Sign(private,runtimeproof.Event{
    Scope:scope,Challenge:challenge,Source:"guest.evdev",
    KeyCode:"key-a",Down:down,EventSequence:seq,
   })
   if err!=nil{return err}
   if err:=enc.Encode(event);err!=nil{return err}
   if down{
    seenDown=true
    fmt.Printf("R27C_REAL_SIGNED_GUEST_DOWN=PASS cycle=%d\n",cycle+1)
    continue
   }
   previousUp=event
   fmt.Printf("R27C_REAL_SIGNED_GUEST_UP=PASS cycle=%d\n",cycle+1)
   cycle++
   if cycle>=2{
    devPath:="/sys/class/input/"+filepath.Base(os.Args[1])
    for j:=0;j<200;j++{
     if _,err:=os.Stat(devPath);os.IsNotExist(err){
      fmt.Println("R27C_GUEST_SYSFS_KEYBOARD_ABSENT=PASS")
      return nil
     }
     time.Sleep(100*time.Millisecond)
    }
    return errors.New("keyboard remains in guest sysfs")
   }
   seenDown=false
   awaitingBind=true
  }
 }

}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"R27C_GUEST_SENSOR=RED",err);os.Exit(1)}
}
