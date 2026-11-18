// Synthetic TEST-ONLY Linux guest evdev sensor. It emits only signed key
// transitions over a virtio-serial character device, NOT host serial console.
// This key is public; no production authentication or real USB/IP implied.
package main

import (
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
  if err:=encoder.Encode(receipt);err!=nil{return err}
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
