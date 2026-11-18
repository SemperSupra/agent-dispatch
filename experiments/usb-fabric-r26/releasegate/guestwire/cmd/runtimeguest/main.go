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
 var scope releasegate.Scope
 var challenge [32]byte
 bind:=func()error{
  var b binding
  if err:=dec.Decode(&b);err!=nil{return err}
  expectedGuest:="r26-l8-qemu-linux"
  expectedDevice:="usb-kbd-a"
  if b.Op!="bind" || b.Scope.GuestID!=expectedGuest ||
   b.Scope.DeviceID!=expectedDevice || b.Scope.HostEpoch=="" ||
   b.Scope.GuestEpoch=="" || b.Scope.LeaseEpoch=="" ||
   b.Scope.Generation==0 || b.Scope.ReleaseSequence==0 ||
   b.Challenge==([32]byte{}){return errors.New("invalid host binding")}
  scope=b.Scope
  challenge=b.Challenge
  fmt.Println("R27C_GUEST_HOST_CHALLENGE_BOUND=PASS")
  return nil
 }
 fmt.Println("R27C_REAL_LINUX_ED25519_EVDEV_READY=PASS")
 if err:=bind();err!=nil{return err}
 var previousUp runtimeproof.Event
 seenDown:=false
 cycle:=0
 for i:=0;i<250000;i++{
  var raw inputEvent
  if err:=binary.Read(ev,binary.LittleEndian,&raw);err!=nil{
   if errors.Is(err,io.EOF){return errors.New("evdev closed before completion")}
   return err
  }
  if raw.Type!=1||raw.Code!=30{continue} // Linux EV_KEY, KEY_A
  down:=raw.Value==1
  if down && seenDown{continue}
  if !down && (raw.Value!=0||!seenDown){continue}
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
   // The guest sysfs absence is a topology TEST witness, not a signed
   // release proof or a production guest attestation statement.
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
  if err:=bind();err!=nil{return err}
  // A real signed first-lease UP is replayed with the OLD challenge:
  // the host must reject even if this process still holds the same key.
  if err:=enc.Encode(previousUp);err!=nil{return err}
  fmt.Println("R27C_GUEST_SIGNED_PRIOR_CHALLENGE_REPLAY_SENT=PASS")
 }
 return errors.New("evdev loop bounded iteration exceeded")
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"R27C_GUEST_SENSOR=RED",err);os.Exit(1)}
}
