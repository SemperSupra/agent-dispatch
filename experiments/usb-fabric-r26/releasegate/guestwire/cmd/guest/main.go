// Synthetic TEST-ONLY Linux guest evdev sensor. It emits only signed key
// transitions over a virtio-serial character device, NOT host serial console.
// This key is public; no production authentication or real USB/IP implied.
package main

import (
 "encoding/binary"
 "encoding/json"
 "fmt"
 "io"
 "os"

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
 if len(os.Args)!=3{return fmt.Errorf("need /dev/input/eventN and virtio-port")}
 ev,err:=os.Open(os.Args[1]);if err!=nil{return err}
 defer ev.Close()
 wire,err:=os.OpenFile(os.Args[2],os.O_WRONLY,0);if err!=nil{return err}
 defer wire.Close()
 encoder:=json.NewEncoder(wire)
 fmt.Println("R26_L8_REAL_GUEST_VIRTIO_EVDEV_OBSERVER_READY=PASS")
 seenDown:=false
 for i:=0;i<100000;i++{
  var e inputEvent
  if err:=binary.Read(ev,binary.LittleEndian,&e);err!=nil{
   if err==io.EOF{return fmt.Errorf("evdev disconnected before key up")}
   return err
  }
  if e.Type!=1||e.Code!=30 {continue} // EV_KEY, Linux KEY_A
  down:=e.Value==1
  if !down && (!seenDown||e.Value!=0){continue}
  if down && seenDown {continue}
  seq:=uint64(10)
  if !down{seq=11}
  receipt:=guestwire.SignForSyntheticGuest(evidence.Event{
   Scope:guestwire.Scope(),Source:"guest.evdev",KeyCode:"key-a",
   Down:down,EventSequence:seq,
  })
  if err:=encoder.Encode(receipt);err!=nil{return err}
  if down {
   seenDown=true
   fmt.Println("R26_L8_REAL_GUEST_VIRTIO_EVDEV_DOWN_SENT=PASS")
  }else{
   fmt.Println("R26_L8_REAL_GUEST_VIRTIO_EVDEV_UP_SENT=PASS")
   return nil
  }
 }
 return fmt.Errorf("evdev observation bound exceeded")
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"R26_L8_GUEST_OBSERVER=RED",err);os.Exit(1)}
}
